"""Pluggable scanner ingestors. Add a new tool by appending to INGESTORS."""

from __future__ import annotations

import json
from pathlib import Path

from remify.ingest.base import Ingestor
from remify.ingest.checkmarx import CheckmarxIngestor
from remify.ingest.sarif import SarifIngestor
from remify.models import Finding

INGESTORS: list[Ingestor] = [CheckmarxIngestor(), SarifIngestor()]


def load_report(path: str | Path) -> list[Finding]:
    report = json.loads(Path(path).read_text())
    for ingestor in INGESTORS:
        if ingestor.detect(report):
            return ingestor.parse(report)
    raise ValueError(f"{path}: no ingestor recognizes this report format")


__all__ = ["INGESTORS", "Ingestor", "load_report"]
