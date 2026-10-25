import shutil
from pathlib import Path

import pytest

from remify.context import build_context
from remify.ingest import load_report
from remify.models import Finding, Location, Severity
from remify.remediate import Edit, RemediationPlan, apply_edits, remediate
from remify.triage import triage

FIXTURES = Path(__file__).parent / "fixtures"


def test_sarif_ingest():
    [f] = load_report(FIXTURES / "semgrep.sarif")
    assert f.tool == "semgrep"
    assert f.cwe == "CWE-89"
    assert f.severity == Severity.MEDIUM
    assert (f.location.path, f.location.start_line) == ("app/db.py", 6)


def test_checkmarx_ingest_uses_sink_node():
    [f] = load_report(FIXTURES / "checkmarx.json")
    assert f.tool == "checkmarx"
    assert f.cwe == "CWE-89"
    assert f.severity == Severity.HIGH
    assert (f.location.path, f.location.start_line) == ("app/db.py", 6)


def test_triage_merges_same_issue_across_tools():
    findings = load_report(FIXTURES / "semgrep.sarif") + load_report(FIXTURES / "checkmarx.json")
    [merged] = triage(findings)
    assert merged.severity == Severity.HIGH
    assert merged.also_reported_by == ["checkmarx"]


def test_context_rejects_path_traversal():
    f = Finding("x", "r", "t", Severity.LOW, Location("../../etc/passwd", 1))
    with pytest.raises(ValueError):
        build_context(f, FIXTURES / "repo")


def test_apply_edits_requires_unique_match():
    with pytest.raises(ValueError):
        apply_edits("a a", [Edit(search="a", replace="b")])


class FakeRemediator:
    def plan(self, finding, ctx):
        return RemediationPlan(
            verdict="true_positive",
            confidence=0.95,
            explanation="Use a parameterized query.",
            edits=[Edit(
                search="""cur.execute("SELECT * FROM users WHERE name = '" + name + "'")""",
                replace="""cur.execute("SELECT * FROM users WHERE name = ?", (name,))""",
            )],
        )


def test_remediate_produces_and_writes_diff(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "repo", repo)
    [f] = load_report(FIXTURES / "checkmarx.json")
    result = remediate(f, repo, FakeRemediator(), write=True)
    assert result.fixed
    assert "+    cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))" in result.diff
    assert "(name,)" in (repo / "app/db.py").read_text()
