"""Contextual remediation: ask the model for a verdict and an exact code edit,
then apply and verify it locally so only fixes that apply cleanly are emitted."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, Field

from remify.context import CodeContext, build_context
from remify.models import Finding

SYSTEM_PROMPT = """You are a senior application-security engineer. You receive one finding \
from a security scanner plus the surrounding source code. Decide whether it is a true \
positive in this context. If it is, produce the smallest correct fix that preserves \
behaviour, as exact search/replace edits against the file. `search` must be copied \
verbatim from the file (without the line-number gutter) and must occur exactly once. \
If it is a false positive, explain why and return no edits."""


class Edit(BaseModel):
    search: str = Field(description="Exact text from the file to replace; must be unique.")
    replace: str


class RemediationPlan(BaseModel):
    verdict: Literal["true_positive", "false_positive", "needs_human"]
    confidence: float = Field(ge=0, le=1)
    explanation: str
    edits: list[Edit]


class Remediator(Protocol):
    def plan(self, finding: Finding, ctx: CodeContext) -> RemediationPlan: ...


@dataclass
class RemediationResult:
    finding: Finding
    plan: RemediationPlan
    diff: str | None
    error: str | None = None

    @property
    def fixed(self) -> bool:
        return bool(self.diff) and self.error is None


class ClaudeRemediator:
    """Default model backend. Credentials come from the environment
    (ANTHROPIC_API_KEY or an `ant auth login` profile)."""

    def __init__(
        self,
        model: str = "claude-opus-5-5",
        effort: str = "high",
        client=None,
        use_fallbacks: bool = True,
    ):
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.effort = effort
        self.use_fallbacks = use_fallbacks

    @classmethod
    def from_deployment(cls, deployment, effort: str = "high") -> "ClaudeRemediator":
        return cls(
            model=deployment.model,
            effort=effort,
            client=deployment.client,
            use_fallbacks=deployment.supports_fallbacks,
        )

    def plan(self, finding: Finding, ctx: CodeContext) -> RemediationPlan:
        prompt = (
            f"Scanner: {finding.tool}\nRule: {finding.rule_id} ({finding.title})\n"
            f"Weakness: {finding.cwe or 'unknown'}\nSeverity: {finding.severity.name}\n"
            f"Location: {finding.location.path}:{finding.location.start_line}\n"
            f"Scanner message: {finding.message}\n\n"
            f"<file path=\"{ctx.path}\" language=\"{ctx.language}\">\n{ctx.file_text}\n</file>\n\n"
            f"<focus>\n{ctx.window}\n</focus>"
        )
        extra = {}
        if self.use_fallbacks:
            # Re-route automatically if a safety classifier declines security content.
            extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        response = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            output_config={"effort": self.effort},
            messages=[{"role": "user", "content": prompt}],
            output_format=RemediationPlan,
            **extra,
        )
        if response.stop_reason == "refusal" or response.parsed_output is None:
            return RemediationPlan(
                verdict="needs_human", confidence=0.0,
                explanation=f"Model returned no plan (stop_reason={response.stop_reason}).",
                edits=[],
            )
        return response.parsed_output


def apply_edits(text: str, edits: list[Edit]) -> str:
    for edit in edits:
        count = text.count(edit.search)
        if count != 1:
            raise ValueError(f"edit search text matched {count} times (expected 1): {edit.search[:60]!r}")
        text = text.replace(edit.search, edit.replace, 1)
    return text


def remediate(
    finding: Finding, repo_root: str | Path, remediator: Remediator, write: bool = False
) -> RemediationResult:
    ctx = build_context(finding, repo_root)
    plan = remediator.plan(finding, ctx)
    if plan.verdict != "true_positive" or not plan.edits:
        return RemediationResult(finding, plan, diff=None)
    try:
        new_text = apply_edits(ctx.file_text, plan.edits)
    except ValueError as exc:
        return RemediationResult(finding, plan, diff=None, error=str(exc))
    diff = "".join(
        difflib.unified_diff(
            ctx.file_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{ctx.path}",
            tofile=f"b/{ctx.path}",
        )
    )
    if write:
        (Path(repo_root) / ctx.path).write_text(new_text)
    return RemediationResult(finding, plan, diff=diff)
