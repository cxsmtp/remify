"""Checkmarx One JSON results ingestor (`/api/results` or CLI `--report-format json`)."""

from __future__ import annotations

from typing import Any

from remify.models import Finding, Location, Severity

_CATEGORY = {"sast": "sast", "sca": "sca", "kics": "iac", "containers": "container"}


class CheckmarxIngestor:
    name = "checkmarx"

    def detect(self, report: Any) -> bool:
        results = report.get("results") if isinstance(report, dict) else None
        return isinstance(results, list) and any(
            isinstance(r, dict) and "similarityId" in r for r in results
        )

    def parse(self, report: dict) -> list[Finding]:
        findings: list[Finding] = []
        for r in report.get("results", []):
            data = r.get("data", {})
            nodes = data.get("nodes") or []
            # The sink (last node) is where the fix usually belongs.
            sink = nodes[-1] if nodes else {}
            path = (sink.get("fileName") or data.get("filename") or "").lstrip("/")
            if not path:
                continue
            cwe_id = r.get("vulnerabilityDetails", {}).get("cweId")
            findings.append(
                Finding(
                    tool="checkmarx",
                    rule_id=str(data.get("queryId") or data.get("queryName") or r.get("id")),
                    title=data.get("queryName") or r.get("description", "")[:80],
                    severity=Severity.parse(r.get("severity")),
                    location=Location(path=path, start_line=int(sink.get("line") or data.get("line") or 1)),
                    message=r.get("description", ""),
                    cwe=f"CWE-{cwe_id}" if cwe_id else None,
                    category=_CATEGORY.get(r.get("type", "sast"), "sast"),
                    raw_id=r.get("id"),
                )
            )
        return findings
