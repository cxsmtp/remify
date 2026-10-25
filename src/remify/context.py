"""Builds the code context the model needs to understand a finding."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from remify.models import Finding

_LANGS = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".cs": "csharp", ".php": "php", ".kt": "kotlin",
    ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
}


@dataclass
class CodeContext:
    path: str
    language: str
    file_text: str
    window: str  # numbered lines around the finding
    window_start: int


def build_context(finding: Finding, repo_root: str | Path, radius: int = 40) -> CodeContext:
    root = Path(repo_root).resolve()
    file_path = (root / finding.location.path).resolve()
    if root not in file_path.parents:
        raise ValueError(f"finding path escapes repository: {finding.location.path}")
    text = file_path.read_text()
    lines = text.splitlines()
    start = max(1, finding.location.start_line - radius)
    end = min(len(lines), finding.location.last_line + radius)
    window = "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))
    return CodeContext(
        path=finding.location.path,
        language=_LANGS.get(file_path.suffix, "text"),
        file_text=text,
        window=window,
        window_start=start,
    )
