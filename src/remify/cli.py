"""Command line entry point.

    remify triage  report1.sarif cx-results.json
    remify fix     report1.sarif --repo . --min-severity high [--write]
"""

from __future__ import annotations

import argparse
import sys

from remify.ingest import load_report
from remify.models import Finding, Severity
from remify.triage import triage


def _load(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        findings.extend(load_report(p))
    return triage(findings)


def _cmd_triage(args: argparse.Namespace) -> int:
    for f in _load(args.reports):
        others = f" (+{', '.join(f.also_reported_by)})" if f.also_reported_by else ""
        print(f"{f.severity.name:<8} {f.location.path}:{f.location.start_line}  "
              f"{f.cwe or '-':<8} {f.title}  [{f.tool}{others}]")
    return 0


def _cmd_fix(args: argparse.Namespace) -> int:
    from remify.remediate import ClaudeRemediator, remediate

    threshold = Severity.parse(args.min_severity)
    remediator = ClaudeRemediator(model=args.model, effort=args.effort)
    for f in _load(args.reports):
        if f.severity < threshold:
            continue
        result = remediate(f, args.repo, remediator, write=args.write)
        print(f"## {f.location.path}:{f.location.start_line} {f.title} -> "
              f"{result.plan.verdict} ({result.plan.confidence:.0%})")
        print(result.plan.explanation)
        if result.error:
            print(f"!! could not apply fix: {result.error}")
        if result.diff:
            print(result.diff)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="remify")
    sub = parser.add_subparsers(dest="command", required=True)

    t = sub.add_parser("triage", help="normalize, dedupe and rank findings from any scanner")
    t.add_argument("reports", nargs="+")
    t.set_defaults(func=_cmd_triage)

    f = sub.add_parser("fix", help="generate contextual fixes for findings")
    f.add_argument("reports", nargs="+")
    f.add_argument("--repo", default=".")
    f.add_argument("--min-severity", default="high")
    f.add_argument("--model", default="claude-opus-5-5")
    f.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    f.add_argument("--write", action="store_true", help="apply fixes to the working tree")
    f.set_defaults(func=_cmd_fix)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
