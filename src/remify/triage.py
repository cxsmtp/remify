"""Cross-tool triage: merge duplicates reported by different scanners and rank."""

from __future__ import annotations

from remify.models import Finding


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        existing = merged.get(f.fingerprint)
        if existing is None:
            merged[f.fingerprint] = f
            continue
        if f.tool != existing.tool and f.tool not in existing.also_reported_by:
            existing.also_reported_by.append(f.tool)
        if f.severity > existing.severity:
            existing.severity = f.severity
    return list(merged.values())


def prioritize(findings: list[Finding]) -> list[Finding]:
    """Highest severity first; agreement between tools raises confidence."""
    return sorted(
        findings,
        key=lambda f: (f.severity, len(f.also_reported_by), f.location.path),
        reverse=True,
    )


def triage(findings: list[Finding]) -> list[Finding]:
    return prioritize(dedupe(findings))
