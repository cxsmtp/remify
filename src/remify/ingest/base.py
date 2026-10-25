from __future__ import annotations

from typing import Any, Protocol

from remify.models import Finding


class Ingestor(Protocol):
    """Converts one scanner's report format into normalized findings."""

    name: str

    def detect(self, report: Any) -> bool:
        """Return True if this ingestor understands the parsed report."""

    def parse(self, report: Any) -> list[Finding]:
        ...
