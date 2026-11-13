"""Portable terminal, JSON, HTML reports and conservative baseline comparison."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import base64
import hashlib
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
    if "name" in report.get("tool", {}) and (not isinstance(report["tool"]["name"], str) or not report["tool"]["name"]):
        raise ValueError("Report tool name must be a non-empty string when supplied")
    warnings = report.get("policy_warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(warning, str) for warning in warnings):
        raise ValueError("Report policy_warnings must be a list of strings")
    if "history_note" in report and not isinstance(report["history_note"], str):
        raise ValueError("Report history_note must be a string")
    if "comparison" in report:
        comparison = report["comparison"]
        keys = {"new", "resolved", "changed", "missing"}
        if (not isinstance(comparison, dict) or not isinstance(comparison.get("summary"), dict)
                or set(comparison["summary"]) != keys
                or any(type(value) is not int or value < 0 for value in comparison["summary"].values())):
            raise ValueError("Report comparison requires non-negative integer new/resolved/changed/missing summary counts")
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


_STATUS_ORDER = {status: index for index, status in enumerate(("FAIL", "WARN", "UNKNOWN", "INFO", "SKIP", "PASS"))}
_SORTS = ("id", "severity", "status", "category")


def _categories(categories):
    if isinstance(categories, str):
        categories = [categories]
    if categories is None:
        return None
    if not isinstance(categories, (list, tuple, set, frozenset)) or any(not isinstance(category, str) or not category for category in categories):
        raise ValueError("Display categories must be non-empty category strings")
    return set(categories)


def select_findings(report_or_list, *, statuses=None, categories=None, min_severity=None, sort_by="id") -> list[dict]:
    """Return an independent display view without changing canonical evidence.

    Filtering never changes report storage or exit-policy input. Severity sorts
    highest first; status sorts review urgency (FAIL/WARN/UNKNOWN before inventory).
    """
    if isinstance(report_or_list, list):
        findings = _findings({"schema_version": 1,
                              "host": {"name": "view", "system": "Linux", "profile": "server"},
                              "findings": report_or_list})
    else:
        findings = _findings(report_or_list)
    if isinstance(statuses, str):
        statuses = [statuses]
    if statuses is not None:
        if not isinstance(statuses, (list, tuple, set, frozenset)) or any(status not in STATUSES for status in statuses):
            raise ValueError("Display statuses must use known finding statuses")
        allowed = set(statuses)
    else:
        allowed = set(STATUSES)
    category_selection = _categories(categories)
    if min_severity is not None and min_severity not in SEVERITIES:
        raise ValueError("Display minimum severity is invalid")
    if sort_by not in _SORTS:
        raise ValueError("Display sort must be id, severity, status, or category")
    minimum = SEVERITIES.index(min_severity) if min_severity is not None else 0
    selected = [finding for finding in findings if finding["status"] in allowed
                and (category_selection is None or finding["category"] in category_selection)
                and SEVERITIES.index(finding["severity"]) >= minimum]
    severity = lambda finding: -SEVERITIES.index(finding["severity"])
    status = lambda finding: _STATUS_ORDER[finding["status"]]
    keys = {"id": lambda f: (f["id"],),
            "severity": lambda f: (severity(f), status(f), f["id"]),
            "status": lambda f: (status(f), severity(f), f["id"]),
            "category": lambda f: (f["category"], f["id"])}
    return deepcopy(sorted(selected, key=keys[sort_by]))


def _priority(findings):
    return select_findings(findings, statuses=("WARN", "FAIL"), sort_by="severity")[:5]


def render_text(report: dict, *, statuses=None, categories=None, min_severity=None, sort_by="id", summary_only=False) -> str:
    findings = _findings(report)
    selected = select_findings(report, statuses=statuses, categories=categories, min_severity=min_severity, sort_by=sort_by)
    host = report["host"]
    counts = Counter(f["status"] for f in findings)
    tool = report.get("tool", {})
    lines = [f"LinScope {tool.get('version', '')} | Linux security configuration report",
             f"Host: {host['name']} | Profile: {host['profile']} | Generated: {report.get('generated_at', 'unknown')}",
             " | ".join(f"{status}: {counts[status]}" for status in STATUSES),
             f"Full report: {len(findings)} findings | Current view: {len(selected)} | Sort: {sort_by}", ""]
    if "history_note" in report:
        lines.append(f"History: {report['history_note']}")
    if "comparison" in report:
        summary = report["comparison"]["summary"]
        lines.append("Previous compatible report: " + " | ".join(f"{key}: {summary[key]}" for key in ("new", "resolved", "changed", "missing")))
    if "history_note" in report or "comparison" in report:
        lines.append("")
    if counts["UNKNOWN"]:
        lines.extend([f"Coverage warning: {counts['UNKNOWN']} UNKNOWN finding(s) in the full report; inaccessible evidence does not establish safety.", ""])
    for warning in report.get("policy_warnings", []):
        lines.append(f"Policy warning: {warning}")
    if report.get("policy_warnings"):
        lines.append("")
    priority = _priority(selected)
    lines.append("Priority review (current view, up to 5 WARN/FAIL findings):")
    for finding in priority:
        lines.append(f"  {finding['id']} / {finding['severity'].upper()} / {finding['status']}: {finding['title']}")
        lines.append(f"    {finding['recommendation']}")
    if not priority:
        lines.append("  No WARN/FAIL findings match this view. This does not establish overall safety.")
    lines.append("")
    if summary_only:
        lines.append("Summary only: detailed evidence is omitted from this display; canonical JSON/history remains complete.")
    for finding in ([] if summary_only else selected):
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


_HTML_SCRIPT = r'''(() => {
  "use strict";
  const root = document.querySelector("main");
  const list = document.getElementById("findings");
  const cards = Array.from(list.querySelectorAll("article.finding"));
  const search = document.getElementById("search");
  const category = document.getElementById("category");
  const severity = document.getElementById("severity");
  const sort = document.getElementById("sort");
  const summary = document.getElementById("summary-only");
  const boxes = Array.from(document.querySelectorAll("input[name=status]"));
  const statusOrder = {FAIL:0,WARN:1,UNKNOWN:2,INFO:3,SKIP:4,PASS:5};
  const compareId = (a,b) => a.dataset.checkId < b.dataset.checkId ? -1 : a.dataset.checkId > b.dataset.checkId ? 1 : 0;
  const compareSeverity = (a,b) => Number(b.dataset.rank)-Number(a.dataset.rank)
      || statusOrder[a.dataset.status]-statusOrder[b.dataset.status] || compareId(a,b);
  const allowed = root.dataset.initialStatuses.split(",").filter(Boolean);
  boxes.forEach(box => { box.checked = allowed.includes(box.value); });
  const initialCategories = JSON.parse(root.dataset.initialCategories);
  if (initialCategories !== null) {
    if (initialCategories.length === 1 && Array.from(category.options).some(option => option.value === initialCategories[0])) {
      category.value = initialCategories[0];
    } else {
      const option = document.createElement("option");
      option.textContent = "Requested categories";
      option.value = "";
      option.dataset.mode = "requested";
      category.appendChild(option);
      category.selectedIndex = category.options.length - 1;
    }
  }
  severity.value = root.dataset.initialMinimum;
  sort.value = root.dataset.initialSort;
  summary.checked = root.dataset.initialSummary === "true";
  function apply() {
    const query = search.value.trim().toLocaleLowerCase();
    const selected = new Set(boxes.filter(box => box.checked).map(box => box.value));
    const selectedCategory = category.selectedOptions[0];
    const visible = cards.filter(card => selected.has(card.dataset.status)
      && Number(card.dataset.rank) >= Number(severity.value)
      && (selectedCategory.dataset.mode === "requested" ? initialCategories.includes(card.dataset.category)
          : !category.value || card.dataset.category === category.value)
      && (!query || card.textContent.toLocaleLowerCase().includes(query)));
    const comparators = {
      id: compareId, severity: compareSeverity,
      status: (a,b) => statusOrder[a.dataset.status]-statusOrder[b.dataset.status] || compareSeverity(a,b),
      category: (a,b) => a.dataset.category < b.dataset.category ? -1 : a.dataset.category > b.dataset.category ? 1 : compareId(a,b)
    };
    cards.slice().sort(comparators[sort.value]).forEach(card => list.appendChild(card));
    const matched = new Set(visible);
    cards.forEach(card => { card.hidden = summary.checked || !matched.has(card); });
    document.getElementById("view-count").textContent = summary.checked
      ? "Summary view: " + visible.length + " matching / " + cards.length + " total findings. All evidence remains in this file."
      : "Showing " + visible.length + " of " + cards.length + " findings. Full-report totals above remain unchanged.";
    document.getElementById("empty-view").hidden = summary.checked || visible.length !== 0;
    const priorities = visible.filter(card => ["WARN","FAIL"].includes(card.dataset.status)).sort(compareSeverity).slice(0,5);
    const priorityList = document.getElementById("priority-list");
    priorityList.replaceChildren();
    priorities.forEach(card => {
      const item = document.createElement("li");
      item.textContent = card.dataset.checkId + " / " + card.dataset.severity.toUpperCase()
        + " / " + card.dataset.status + ": " + card.querySelector("h2").textContent;
      priorityList.appendChild(item);
    });
    if (!priorities.length) {
      const item = document.createElement("li");
      item.textContent = "No WARN/FAIL findings match this view. This does not establish overall safety.";
      priorityList.appendChild(item);
    }
  }
  [search,category,severity,sort,summary,...boxes].forEach(control => control.addEventListener("input",apply));
  document.getElementById("reset-view").addEventListener("click",() => {
    search.value = ""; category.selectedIndex = 0; severity.value = "0"; sort.value = "id"; summary.checked = false;
    boxes.forEach(box => { box.checked = true; }); apply();
  });
  document.getElementById("expand-all").addEventListener("click",() => cards.forEach(card => { card.querySelector("details").open = true; }));
  document.getElementById("collapse-all").addEventListener("click",() => cards.forEach(card => { card.querySelector("details").open = false; }));
  apply();
  document.documentElement.classList.add("js");
})();'''


def render_html(report: dict, *, statuses=None, categories=None, min_severity=None, sort_by="id", summary_only=False) -> str:
    """Render a self-contained report; display controls never discard evidence.

    All cards/details are initially visible without JavaScript. The hashed
    static script applies the requested initial view and enables local controls.
    Dynamic evidence is escaped markup, never interpolated into executable code.
    """
    findings = _findings(report)
    selected = select_findings(report, statuses=statuses, categories=categories, min_severity=min_severity, sort_by=sort_by)
    # Canonical cards all remain present even if the requested display is empty.
    ordered = select_findings(report, sort_by=sort_by)
    selected_ids = {finding["id"] for finding in selected}
    initial_statuses = list(STATUSES) if statuses is None else ([statuses] if isinstance(statuses, str) else list(statuses))
    selected_categories = _categories(categories)
    initial_categories = None if selected_categories is None else sorted(selected_categories)
    esc = lambda value: escape(str(value), quote=True)
    host = report["host"]
    counts = Counter(f["status"] for f in findings)
    tiles = "".join(f'<div class="metric {status.lower()}"><strong>{counts[status]}</strong><span>{status}</span></div>' for status in STATUSES)
    cards = []
    warnings_html = ""
    if report.get("policy_warnings"):
        warnings_html = ('<aside class="policy-warnings"><strong>Policy warnings</strong><ul>'
                         + "".join(f"<li>{esc(warning)}</li>" for warning in report["policy_warnings"])
                         + "</ul></aside>")
    coverage = (f'<aside class="coverage"><strong>Coverage warning</strong>: {counts["UNKNOWN"]} UNKNOWN finding(s) '
                'in the full report. Missing evidence does not establish safety.</aside>') if counts["UNKNOWN"] else ""
    history_html = f'<p class="sub">History: {esc(report["history_note"])}</p>' if "history_note" in report else ""
    comparison_html = ""
    if "comparison" in report:
        summary = report["comparison"]["summary"]
        comparison_html = ('<aside class="notice"><strong>Previous compatible report</strong>: '
                           + " · ".join(f"{key}: {summary[key]}" for key in ("new", "resolved", "changed", "missing")) + "</aside>")
    for index, finding in enumerate(ordered, 1):
        exception_html = ""
        if "exception" in finding:
            exception = finding["exception"]
            state = "Active" if exception["active"] else "Expired"
            exception_html = (f'<aside class="exception"><strong>{state} exception</strong> · expires '
                              f'{esc(exception["expires"])}<p>{esc(exception["reason"])}</p>'
                              '<small>Original status and severity remain unchanged.</small></aside>')
        cards.append(f'''<article id="finding-{index}" class="finding" data-check-id="{esc(finding['id'])}" data-category="{esc(finding['category'])}" data-status="{finding['status']}" data-severity="{finding['severity']}" data-rank="{SEVERITIES.index(finding['severity'])}">
<div class="finding-top"><span class="badge {finding['status'].lower()}">{finding['status']}</span>
<span class="eyebrow">{esc(finding['id'])} · {esc(finding['category'])} · {finding['severity']}</span></div>
<h2>{esc(finding['title'])}</h2><details open><summary>Evidence and recommendation</summary>
<dl><dt>Evidence</dt><dd>{esc(finding['evidence'])}</dd>
<dt>Recommendation</dt><dd>{esc(finding['recommendation'])}</dd></dl>{exception_html}</details></article>''')
    priority = _priority(selected)
    priority_html = "".join(f'<li>{esc(f["id"])} / {f["severity"].upper()} / {f["status"]}: {esc(f["title"])}</li>' for f in priority)
    if not priority_html:
        priority_html = '<li>No WARN/FAIL findings match this view. This does not establish overall safety.</li>'
    status_controls = "".join(f'<label><input type="checkbox" name="status" value="{status}" checked> {status}</label>' for status in STATUSES)
    category_options = "".join(f'<option value="{esc(category)}">{esc(category)}</option>' for category in sorted({f["category"] for f in findings}))
    severities = "".join(f'<option value="{index}">{severity.title()} and above</option>' for index, severity in enumerate(SEVERITIES))
    script_hash = base64.b64encode(hashlib.sha256(_HTML_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    initial_minimum = SEVERITIES.index(min_severity) if min_severity is not None else 0
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
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
.notice,.coverage{{border-left:3px solid #136b72;background:#e7f1f2;padding:15px 19px;margin-bottom:20px;color:#264e55}}
.coverage{{border-color:#6952a0;background:#efebf7;color:#53417b}}
.policy-warnings{{border-left:3px solid #a76910;background:#fff5df;padding:15px 19px;margin-bottom:20px;color:#73521a}}.policy-warnings ul{{margin:6px 0 0;padding-left:20px;overflow-wrap:anywhere}}
.priority{{border:1px solid var(--line);background:white;padding:18px 22px;border-radius:10px;margin:24px 0}}.priority h2{{margin-top:0}}.priority li{{overflow-wrap:anywhere;margin:8px 0}}
.tools{{display:none;background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin:24px 0}}.js .tools{{display:block}}
.tool-grid{{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:12px}}.tool-grid label{{font-size:12px;font-weight:650}}input[type=search],select{{display:block;width:100%;padding:10px;margin-top:5px;border:1px solid #a9bbc8;border-radius:6px;background:white;color:var(--ink);font:inherit}}
fieldset{{border:0;padding:12px 0;margin:8px 0}}fieldset legend{{font-size:12px;font-weight:650}}fieldset label{{display:inline-block;margin:5px 16px 5px 0;font-size:12px}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}button{{font:inherit;font-size:12px;padding:8px 12px;border:1px solid #a9bbc8;border-radius:6px;background:#f8fbfd;color:var(--ink);cursor:pointer}}button:hover{{background:#e7f1f2}}:focus-visible{{outline:3px solid #136b72;outline-offset:2px}}
.view-count{{font-size:13px;color:var(--muted)}}.nojs{{font-size:13px;color:var(--muted)}}.js .nojs{{display:none}}[hidden]{{display:none!important}}
.finding{{border:1px solid var(--line);background:var(--paper);border-radius:12px;margin:16px 0;padding:24px;break-inside:avoid}}
.finding-top{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}.badge{{border:1px solid currentColor;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:750;letter-spacing:.05em}}
.eyebrow{{color:var(--muted);font-size:12px;overflow-wrap:anywhere}}h2{{font-size:20px;margin:14px 0 18px;line-height:1.35}}
summary{{cursor:pointer;font-size:13px;color:#136b72;font-weight:650}}dl{{margin:0}}dt{{font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-top:14px}}dd{{margin:5px 0;white-space:pre-wrap;overflow-wrap:anywhere}}
.exception{{background:#fff5df;border:1px solid #e8d8b2;border-radius:6px;margin-top:18px;padding:12px 15px;color:#73521a}}.exception p{{margin:4px 0}}
footer{{margin-top:32px;font-size:12px;color:var(--muted)}}@media(max-width:800px){{.tool-grid{{grid-template-columns:1fr 1fr}}}}@media(max-width:700px){{main{{padding:26px 16px}}h1{{font-size:32px}}.metrics{{grid-template-columns:repeat(3,1fr)}}.finding{{padding:18px}}}}
@media print{{body{{background:white}}main{{padding:0;max-width:none}}h1{{font-size:30px}}.tools{{display:none!important}}.metric,.finding{{box-shadow:none}}.finding{{border-radius:0}}}}
</style></head><body><main data-initial-statuses="{esc(','.join(initial_statuses))}" data-initial-categories="{esc(json.dumps(initial_categories, ensure_ascii=True))}" data-initial-minimum="{initial_minimum}" data-initial-sort="{sort_by}" data-initial-summary="{str(bool(summary_only)).lower()}">
<header><div class="brand">LinScope / Security configuration</div>
<h1>Host security review</h1><p class="sub">Read-only checks, observable evidence, and actionable recommendations.</p>
<div class="metadata"><span><strong>Host</strong> {esc(host['name'])}</span><span><strong>Profile</strong> {esc(host['profile'])}</span>
<span><strong>System</strong> {esc(host['system'])} {esc(host.get('release', ''))}</span>
<span><strong>Generated</strong> {esc(report.get('generated_at', 'unknown'))}</span>
<span><strong>Version</strong> {esc(report.get('tool', {}).get('version', 'unknown'))}</span></div>{history_html}</header>
<section class="metrics" aria-label="Full-report finding totals">{tiles}</section>
<aside class="notice">Totals cover the full report. Filters affect display only. All {len(findings)} findings and their evidence remain in this file.
UNKNOWN means evidence could not be established. SKIP includes inapplicable or explicitly disabled checks; neither establishes safety.</aside>
{comparison_html}{coverage}{warnings_html}
<section class="tools" aria-label="Report display controls"><div class="tool-grid">
<label for="search">Search findings<input id="search" type="search" placeholder="ID, title, evidence, recommendation"></label>
<label for="category">Category<select id="category"><option value="" data-mode="all">All categories</option>{category_options}</select></label>
<label for="severity">Minimum severity<select id="severity">{severities}</select></label>
<label for="sort">Sort by<select id="sort"><option value="id">Check ID</option><option value="severity">Severity</option><option value="status">Status</option><option value="category">Category</option></select></label>
</div><fieldset><legend>Statuses to show</legend>{status_controls}</fieldset>
<div class="actions"><label><input id="summary-only" type="checkbox"> Summary only</label><button id="reset-view" type="button">Show all / reset</button><button id="expand-all" type="button">Expand details</button><button id="collapse-all" type="button">Collapse details</button></div></section>
<p class="view-count" id="view-count" role="status">Requested view: {len(selected_ids)} / {len(findings)} findings. Full evidence is shown until local display controls are enabled.</p>
<p class="nojs">JavaScript is optional. Without it, all findings and open details remain available; browser search still works.</p>
<section class="priority" aria-label="Priority review"><h2>Priority review</h2><p class="sub">Up to five WARN/FAIL findings from the current view, ordered by severity. This is not an overall security score.</p><ol id="priority-list">{priority_html}</ol></section>
<p id="empty-view" hidden>No findings match the current display filters. Reset the view to see the complete report.</p>
<section id="findings" aria-label="Findings">{''.join(cards) if cards else '<p>No findings were produced for the selected scope.</p>'}</section>
<footer>Generated by LinScope. This report reflects collected configuration evidence and does not certify that a host is free of vulnerabilities.</footer>
</main><script type="text/javascript">{_HTML_SCRIPT}</script></body></html>\n'''


def compare_reports(old: dict, new: dict) -> dict:
    """Compare compatible reports; only WARN/FAIL -> PASS is a resolution.

    Missing checks and transitions to UNKNOWN/SKIP are never resolutions. Scope
    changes are rejected instead of manufacturing improvements in the report.
    """
    old_findings, new_findings = _findings(old), _findings(new)
    old_name, new_name = old.get("tool", {}).get("name"), new.get("tool", {}).get("name")
    if old_name is not None and new_name is not None and old_name != new_name:
        raise ValueError("Cannot compare reports from different tools")
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
