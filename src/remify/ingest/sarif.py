"""SARIF 2.1.0 ingestor.

SARIF is the common denominator for most scanners (Semgrep, CodeQL, Snyk Code,
Trivy, Checkov, GitHub code scanning, Checkmarx export), so this single adapter
already covers the majority of the ecosystem.
"""

from __future__ import annotations

import re
from typing import Any

from remify.models import Finding, Location, Severity

_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _cwe_from(*texts: Any) -> str | None:
    for text in texts:
        if isinstance(text, (list, tuple)):
            found = _cwe_from(*text)
            if found:
                return found
        elif isinstance(text, str):
            m = _CWE.search(text)
            if m:
                return f"CWE-{m.group(1)}"
    return None


class SarifIngestor:
    name = "sarif"

    def detect(self, report: Any) -> bool:
        return isinstance(report, dict) and "runs" in report and (
            "sarif" in str(report.get("$schema", "")).lower() or "version" in report
        )

    def parse(self, report: dict) -> list[Finding]:
        findings: list[Finding] = []
        for run in report.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool = driver.get("name", "unknown").lower()
            rules = {r.get("id"): r for r in driver.get("rules", [])}
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                phys = (result.get("locations") or [{}])[0].get("physicalLocation", {})
                region = phys.get("region", {})
                path = phys.get("artifactLocation", {}).get("uri", "")
                if not path:
                    continue
                props = {**rule.get("properties", {}), **result.get("properties", {})}
                level = (
                    props.get("severity")
                    or props.get("problem.severity")
                    or result.get("level")
                    or rule.get("defaultConfiguration", {}).get("level")
                )
                findings.append(
                    Finding(
                        tool=tool,
                        rule_id=rule_id,
                        title=rule.get("shortDescription", {}).get("text") or rule_id,
                        severity=Severity.parse(level),
                        location=Location(
                            path=path.removeprefix("file://"),
                            start_line=region.get("startLine", 1),
                            end_line=region.get("endLine"),
                        ),
                        message=result.get("message", {}).get("text", ""),
                        cwe=_cwe_from(props.get("tags"), props.get("cwe"), rule_id),
                    )
                )
        return findings
