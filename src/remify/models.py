"""Normalized data model shared by every ingestor and the remediation engine.

Every scanner (Checkmarx, Semgrep, CodeQL, Snyk, Trivy, ...) is mapped onto
`Finding`, so triage and remediation never depend on a specific vendor.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        aliases = {
            "note": cls.LOW,
            "warning": cls.MEDIUM,
            "error": cls.HIGH,
            "informational": cls.INFO,
            "information": cls.INFO,
        }
        if not value:
            return cls.MEDIUM
        key = value.strip().lower()
        if key in aliases:
            return aliases[key]
        try:
            return cls[key.upper()]
        except KeyError:
            return cls.MEDIUM


@dataclass
class Location:
    path: str
    start_line: int
    end_line: int | None = None

    @property
    def last_line(self) -> int:
        return self.end_line or self.start_line


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: Severity
    location: Location
    message: str = ""
    cwe: str | None = None
    category: str = "sast"  # sast | sca | iac | secret | container
    raw_id: str | None = None
    # Populated by triage when the same issue is reported by several tools.
    also_reported_by: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Tool-independent identity: same file, same line, same weakness."""
        weakness = self.cwe or self.rule_id.lower()
        key = f"{self.location.path}:{self.location.start_line}:{weakness}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def id(self) -> str:
        return self.fingerprint
