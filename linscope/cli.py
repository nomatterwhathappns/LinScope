"""Command-line orchestration; checks are separate from rendering and exit policy."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import platform
import sys

from linscope import __version__
from linscope.core import Context, SEVERITIES, STATUSES, unavailable
from linscope.history import latest_compatible, list_history, save_report
from linscope.policy import apply_exceptions, load_policy, parse_ssh_context, validate_paths, validate_service_units, validate_ssh_contexts, validate_users
from linscope.registry import CHECKS
from linscope.preflight import inspect_capabilities, render_preflight_text
from linscope.reporting import _plain, compare_reports, render_html, render_json, render_text
from linscope.rules import build_rules_snapshot, mark_rules_unstable


def collect(ctx, categories):
    initial_rules = build_rules_snapshot(ctx, categories)
    findings = []
    for number, category in enumerate(categories, 1):
        if getattr(ctx, "progress", False):
            print(f"[{number}/{len(categories)}] Checking {category}", file=sys.stderr)
        try:
            findings.extend(CHECKS[category](ctx))
        except Exception as exc:
            # Isolate a collector failure; retain all other categories and visibly
            # flag incomplete coverage instead of producing a clean report.
            findings.append(unavailable(f"{category.upper()}-ERROR", category,
                                        "Collector failed; coverage incomplete", f"{type(exc).__name__}: {exc}"))
    ids = [finding.id for finding in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate check IDs detected")
    report = {
        "schema_version": 1,
        "tool": {"name": "LinScope", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": {"name": platform.node(), "system": platform.system(),
                 "release": platform.release(), "profile": ctx.profile},
        "scope": {"checks": sorted(categories), "deep": ctx.deep},
        "findings": [finding.to_dict() for finding in findings],
    }
    parameters = {key: getattr(ctx, key) for key in ("baseline", "ssh_contexts", "sudo_users", "user_paths", "service_units") if getattr(ctx, key, None)}
    if "acl" in categories or "userfiles" in categories or ("sudo" in categories and not getattr(ctx, "sudo_users", None)):
        parameters["identity_uid"] = os.getuid()
    if parameters:
        report["scope"]["parameters"] = parameters
    report["rules"] = build_rules_snapshot(ctx, categories)
    if initial_rules["fingerprint"] != report["rules"]["fingerprint"]:
        report["rules"] = mark_rules_unstable(report["rules"])
    if not report["rules"]["complete"]:
        report["policy_warnings"] = ["Rule source identity is incomplete or changed during collection; this snapshot cannot be used for a verified rule comparison."]
    return report


def load_report(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate report key: {key}")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")
    # Context.read bounds bytes and rejects FIFOs/special files. Resolve a
    # relative CLI path against cwd rather than the audited filesystem root.
    from pathlib import Path
    raw = Context().read(str(Path(path).absolute()), limit=8_388_608)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def render_comparison(comparison):
    lines = ["LinScope / Report comparison", " | ".join(f"{k}: {v}" for k, v in comparison["summary"].items()), ""]
    if comparison.get("rules_verified") is False:
        lines.append("Legacy comparison: assessment rules are unverified; status changes do not establish verified remediation.")
    for group in ("new", "resolved", "changed", "missing"):
        lines.append(group.upper())
        for item in comparison[group]:
            if "before" in item:
                before, after = item["before"], item["after"]
                lines.append(f"  {item['id']}: {before['status']} -> {after['status']} | {after['title']}")
            else:
                lines.append(f"  {item['id']}: {item['status']} | {item['title']}")
        if not comparison[group]:
            lines.append("  (none)")
    lines.append("Missing checks and transitions to UNKNOWN/SKIP are never counted as resolved.")
    return "\n".join(lines) + "\n"


def write_output(content, path):
    if path is None:
        # Avoid terminal escape injection from host-controlled names/configuration.
        clean = "".join(c if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) < 160) else "?" for c in content)
        print(clean, end="")
        return
    # Exclusive creation prevents accidental overwrite and symlink following.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="linscope", description="Read-only Linux security configuration checks with evidence-based reports.")
    parser.add_argument("--version", action="version", version=f"LinScope {__version__}")
    parser.add_argument("--profile", choices=("server", "desktop", "router", "container"), help="Host role; overrides policy (default: server).")
    parser.add_argument("--category", action="append", choices=sorted(CHECKS), help="Select a category (repeatable); default: all.")
    parser.add_argument("--list-categories", action="store_true")
    parser.add_argument("--deep", action="store_true", help="Enable bounded optional filesystem searches.")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("--output", metavar="PATH", help="Create a private report file; existing files are never overwritten.")
    parser.add_argument("--fail-on", choices=SEVERITIES[1:], help="Exit 1 for WARN/FAIL at this severity or higher.")
    parser.add_argument("--fail-on-unknown", action="store_true", help="Exit 2 when checks or recorded rule identities have incomplete coverage.")
    parser.add_argument("--policy", metavar="JSON", help="Load declarative profile/categories and expiring exceptions.")
    parser.add_argument("--ssh-context", action="append", metavar="USER_ADDR_HOST", help="Evaluate SSH Match context: user=alice,addr=192.0.2.1,host=client.example (repeatable).")
    parser.add_argument("--sudo-user", action="append", metavar="USER", help="List effective sudo policy for a selected user without executing grants (repeatable).")
    parser.add_argument("--service-unit", action="append", metavar="UNIT.service", help="Inspect selected system service hardening properties (repeatable; otherwise bounded running-service discovery).")
    parser.add_argument("--user-path", action="append", metavar="ABSOLUTE_PATH", help="Review additional user credential/configuration metadata without reading contents (repeatable).")
    parser.add_argument("--honor-exceptions", action="store_true", help="Exclude active policy exceptions from --fail-on only; findings remain visible.")
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="Compare compatible JSON reports offline (text/JSON output).")
    parser.add_argument("--status", action="append", choices=STATUSES, help="Display only this status (repeatable); exit gates and stored JSON/history stay complete.")
    parser.add_argument("--min-severity", choices=SEVERITIES, help="Display findings at or above this severity.")
    parser.add_argument("--view-category", choices=sorted(CHECKS), help="Display one category without changing collected scope.")
    parser.add_argument("--sort", choices=("id", "severity", "status", "category"), help="Sort the display (default: id).")
    parser.add_argument("--summary", action="store_true", help="Show counts, priority review, and coverage without detailed evidence.")
    parser.add_argument("--progress", action="store_true", help="Write category progress to stderr, keeping JSON stdout clean.")
    parser.add_argument("--preflight", action="store_true", help="Inspect available commands and representative read access without scanning.")
    parser.add_argument("--history-dir", metavar="PATH", help="Save complete JSON snapshots in an opt-in private local directory.")
    parser.add_argument("--history-list", action="store_true", help="List saved snapshots from --history-dir without scanning.")
    parser.add_argument("--compare-latest", action="store_true", help="Compare with the latest compatible snapshot before saving this scan.")
    args = parser.parse_args(argv)
    view_active = bool(args.status or args.min_severity or args.view_category or args.sort or args.summary)
    if args.format == "json" and view_active:
        parser.error("JSON reports are always complete; display filters/sorting/summary require text or HTML")
    if (args.history_list or args.compare_latest) and not args.history_dir:
        parser.error("--history-list and --compare-latest require --history-dir")
    scan_options = bool(args.profile or args.category or args.deep or args.policy or args.fail_on or args.fail_on_unknown
                        or args.honor_exceptions or args.ssh_context or args.sudo_user or args.progress or args.service_unit or args.user_path)
    if args.compare:
        if scan_options or args.list_categories or args.preflight or args.history_dir or args.history_list or args.compare_latest or view_active:
            parser.error("--compare cannot be combined with live-check or policy options")
        if args.format == "html":
            parser.error("--compare supports --format text or json; HTML is available for scan reports")
        try:
            comparison = compare_reports(load_report(args.compare[0]), load_report(args.compare[1]))
            content = json.dumps(comparison, indent=2, ensure_ascii=True) + "\n" if args.format == "json" else render_comparison(comparison)
            write_output(content, args.output)
            return 0
        except (OSError, ValueError, RecursionError) as exc:
            print(_plain(f"linscope: {exc}"), file=sys.stderr)
            return 2
    if args.history_list:
        if scan_options or args.preflight or args.compare_latest or args.list_categories or view_active or args.format == "html":
            parser.error("--history-list supports text/JSON output and cannot be combined with scan options")
        try:
            entries = list_history(args.history_dir)
            if args.format == "json":
                content = json.dumps({"kind": "history", "entries": entries}, indent=2, ensure_ascii=True) + "\n"
            else:
                rows = ["LinScope / Local report history (newest saved first)"]
                rows.extend(f"{row['name']} | {row['host']} | {row['profile']} | v{row['version']} | {row['findings_count']} findings" for row in entries)
                content = "\n".join(rows + ([] if entries else ["No saved snapshots."])) + "\n"
            write_output(content, args.output)
            return 0
        except (OSError, ValueError, RecursionError) as exc:
            print(_plain(f"linscope: {exc}"), file=sys.stderr)
            return 2
    if args.list_categories:
        print("\n".join(CHECKS))
        return 0
    if args.honor_exceptions and not (args.policy and args.fail_on):
        parser.error("--honor-exceptions requires both --policy and --fail-on")
    if args.preflight and (args.history_dir or args.compare_latest or args.fail_on or args.fail_on_unknown or args.honor_exceptions or view_active or args.format == "html"):
        parser.error("--preflight supports text/JSON capability output; scan gates, history and display filters do not apply")
    if platform.system() != "Linux":
        parser.error("Live checks require Linux. Reports and source can be inspected on other platforms.")
    try:
        policy = load_policy(args.policy) if args.policy else {}
        categories = list(dict.fromkeys(args.category or policy.get("checks") or CHECKS))
        ssh_contexts = validate_ssh_contexts([parse_ssh_context(value) for value in args.ssh_context]) if args.ssh_context else policy.get("ssh_contexts", [])
        sudo_users = validate_users(args.sudo_user) if args.sudo_user else policy.get("sudo_users", [])
        user_paths = validate_paths(args.user_path) if args.user_path else policy.get("user_paths", [])
        service_units = validate_service_units(args.service_unit) if args.service_unit else policy.get("service_units", [])
        context_options = {"profile": args.profile or policy.get("profile", "server"), "deep": args.deep}
        for key, value in (("baseline", policy.get("baseline", {})), ("ssh_contexts", ssh_contexts), ("sudo_users", sudo_users),
                           ("user_paths", user_paths), ("service_units", service_units)):
            if value:
                context_options[key] = value
        ctx = Context(**context_options)
        if args.preflight:
            capabilities = inspect_capabilities(ctx, categories)
            content = json.dumps(capabilities, indent=2, ensure_ascii=True) + "\n" if args.format == "json" else render_preflight_text(capabilities)
            write_output(content, args.output)
            return 0
        if args.progress:
            ctx.progress = True
        report = collect(ctx, categories)
        if args.policy:
            report["findings"] = apply_exceptions(report["findings"], policy)
            emitted = {f["id"] for f in report["findings"]}
            unmatched = sorted(set(policy.get("exceptions", {})) - emitted)
            report.setdefault("policy_warnings", []).extend(f"Exception {check_id} was not evaluated: ID absent from the selected report (excluded scope, unavailable evidence, or a typo)." for check_id in unmatched)
        if args.compare_latest:
            previous = latest_compatible(args.history_dir, report)
            if previous is None:
                report["history_note"] = "No compatible previous snapshot was found; this scan establishes the selected history baseline."
            else:
                report["comparison"] = compare_reports(previous, report)
        view_options = {}
        for key, value in (("statuses", args.status), ("min_severity", args.min_severity),
                           ("categories", [args.view_category] if args.view_category else None),
                           ("sort_by", args.sort), ("summary_only", args.summary)):
            if value:
                view_options[key] = value
        if args.format == "json":
            rendered = render_json(report)
        else:
            rendered = {"text": render_text, "html": render_html}[args.format](report, **view_options)
        write_output(rendered, args.output)
        if args.history_dir:
            saved = save_report(args.history_dir, report)
            print(_plain(f"History saved: {saved}"), file=sys.stderr)
    except (OSError, ValueError, RecursionError) as exc:
        print(_plain(f"linscope: {exc}"), file=sys.stderr)
        return 2
    if args.fail_on_unknown and (any(f["status"] == "UNKNOWN" for f in report["findings"])
                                 or report.get("rules", {}).get("complete") is False):
        return 2
    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        if any(f["status"] in ("WARN", "FAIL") and SEVERITIES.index(f["severity"]) >= threshold
               and not (args.honor_exceptions and f.get("exception", {}).get("active", False)) for f in report["findings"]):
            return 1
    return 0
