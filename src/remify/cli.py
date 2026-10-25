"""Command line entry point.

    remify triage  report1.sarif cx-results.json
    remify fix     report1.sarif --repo . --min-severity high [--write] [--deployment bedrock]
    remify verify  fixes.json

Set REMIFY_SIGNING_KEY to sign every fix (written to fixes.json) so CI can
verify it was not altered after Remify produced it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

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
    from remify import deploy, integrity
    from remify.remediate import ClaudeRemediator, remediate

    threshold = Severity.parse(args.min_severity)
    deployment = deploy.from_env(args.deployment, model=args.model)
    remediator = ClaudeRemediator.from_deployment(deployment, effort=args.effort)
    key = os.environ.get("REMIFY_SIGNING_KEY", "").encode()
    signed: list[dict] = []
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
            if key:
                signed.append({**integrity.sign(f.id, result.diff, key), "diff": result.diff})
    if signed:
        Path(args.out).write_text(json.dumps(signed, indent=2))
        print(f"wrote {len(signed)} signed fix(es) to {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from remify import integrity

    key = os.environ.get("REMIFY_SIGNING_KEY", "").encode()
    if not key:
        print("REMIFY_SIGNING_KEY is not set", file=sys.stderr)
        return 2
    bad = 0
    for record in json.loads(Path(args.fixes).read_text()):
        ok = integrity.verify(record, record["diff"], key)
        bad += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {record['finding']}")
    return 1 if bad else 0


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
    f.add_argument("--deployment", choices=["saas", "bedrock", "vertex", "foundry"],
                   help="where the model runs (default: $REMIFY_DEPLOYMENT or saas)")
    f.add_argument("--out", default="fixes.json", help="signed fixes output (needs REMIFY_SIGNING_KEY)")
    f.set_defaults(func=_cmd_fix)

    v = sub.add_parser("verify", help="check signatures on fixes produced by `remify fix`")
    v.add_argument("fixes")
    v.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
