"""Command-line orchestration; checks are separate from rendering and exit policy."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
import platform
import sys

from linscope import __version__
from linscope.core import Context, SEVERITIES, unavailable
from linscope.registry import CHECKS


def collect(ctx, categories):
    findings = []
    for category in categories:
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
    return {
        "schema_version": 1,
        "tool": {"name": "LinScope", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": {"name": platform.node(), "system": platform.system(),
                 "release": platform.release(), "profile": ctx.profile},
        "scope": {"checks": sorted(categories), "deep": ctx.deep},
        "findings": [finding.to_dict() for finding in findings],
    }


def render_text(report):
    counts = Counter(f["status"] for f in report["findings"])
    lines = [f"LinScope {report['tool']['version']} | profile: {report['host']['profile']}",
             f"Host: {report['host']['name']} | generated: {report['generated_at']}",
             "  ".join(f"{status}: {counts[status]}" for status in ("PASS", "WARN", "FAIL", "UNKNOWN", "SKIP", "INFO")), ""]
    for finding in report["findings"]:
        lines.extend([f"[{finding['status']}] {finding['id']} ({finding['severity']}) {finding['title']}",
                      f"  Evidence: {finding['evidence']}", f"  Recommendation: {finding['recommendation']}", ""])
    lines.append("Configuration review only; PASS applies to the stated check, not overall host security.")
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
    parser.add_argument("--profile", choices=("server", "desktop", "router", "container"), default="server")
    parser.add_argument("--category", action="append", choices=sorted(CHECKS), help="Select a category (repeatable); default: all.")
    parser.add_argument("--list-categories", action="store_true")
    parser.add_argument("--deep", action="store_true", help="Enable bounded optional filesystem searches.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", metavar="PATH", help="Create a private report file; existing files are never overwritten.")
    parser.add_argument("--fail-on", choices=SEVERITIES[1:], help="Exit 1 for WARN/FAIL at this severity or higher.")
    parser.add_argument("--fail-on-unknown", action="store_true", help="Exit 2 when any check has UNKNOWN coverage.")
    args = parser.parse_args(argv)
    if args.list_categories:
        print("\n".join(CHECKS))
        return 0
    if platform.system() != "Linux":
        parser.error("Live checks require Linux. Reports and source can be inspected on other platforms.")
    categories = list(dict.fromkeys(args.category or CHECKS))
    try:
        report = collect(Context(profile=args.profile, deep=args.deep), categories)
        rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n" if args.format == "json" else render_text(report)
        write_output(rendered, args.output)
    except (OSError, ValueError) as exc:
        print(f"linscope: {exc}", file=sys.stderr)
        return 2
    if args.fail_on_unknown and any(f["status"] == "UNKNOWN" for f in report["findings"]):
        return 2
    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        if any(f["status"] in ("WARN", "FAIL") and SEVERITIES.index(f["severity"]) >= threshold for f in report["findings"]):
            return 1
    return 0
