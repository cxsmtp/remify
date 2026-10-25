# Remify

**Read → triage → remediate, for any security scanner.**

Scanners such as Checkmarx, Semgrep, CodeQL, Snyk and Trivy are good at *finding*
problems. Remify is the layer above them: it reads results from any tool,
merges duplicates, works out whether each finding is real *in context*, and
produces a verified code fix instead of another ticket for someone to review by hand.

```
Security tool reports ──► Ingest (normalize) ──► Triage (dedupe + rank)
   SARIF, Checkmarx, …                                   │
                                                         ▼
                       Context builder (code around the finding, language)
                                                         │
                                                         ▼
                 Remediation engine (Claude) ──► verified diff / PR
                                                         │
                                       ┌─────────────────┴────────────────┐
                                SaaS (Remify cloud)           Customer-managed
```

## Quick start

```bash
pip install -e '.[dev]'
export ANTHROPIC_API_KEY=...            # or `ant auth login`

# Normalize, dedupe and rank results from several tools
remify triage semgrep.sarif checkmarx.json

# Generate contextual fixes for high+ findings (prints diffs)
remify fix semgrep.sarif checkmarx.json --repo . --min-severity high

# ...and apply them to the working tree
remify fix semgrep.sarif --repo . --write

# Customer-managed: run on the customer's own Claude endpoint
REMIFY_AWS_REGION=us-east-1 remify fix semgrep.sarif --deployment bedrock

# Sign fixes, then verify them in CI before merge
REMIFY_SIGNING_KEY=... remify fix semgrep.sarif --out fixes.json
REMIFY_SIGNING_KEY=... remify verify fixes.json
```

| Deployment | Selected by | Required env |
|---|---|---|
| `saas` (default) | `--deployment saas` | `ANTHROPIC_API_KEY` or `ant auth login` |
| `bedrock` | `--deployment bedrock` | `REMIFY_AWS_REGION` + AWS credentials |
| `vertex` | `--deployment vertex` | `REMIFY_GCP_PROJECT`, optional `REMIFY_GCP_REGION` + gcloud ADC |
| `foundry` | `--deployment foundry` | `REMIFY_FOUNDRY_RESOURCE`, `REMIFY_FOUNDRY_API_KEY` |

## How it works

| Stage | Module | What it does |
|---|---|---|
| Ingest | `remify/ingest/` | Maps each tool's format onto one `Finding` model. SARIF covers most tools; Checkmarx One JSON has its own adapter. New tools = one class with `detect()` + `parse()`. |
| Triage | `remify/triage.py` | Fingerprints findings by file + line + CWE so the same bug reported by two tools becomes one item (higher severity wins, agreement is recorded). |
| Context | `remify/context.py` | Loads the file and a numbered window around the finding; refuses paths that escape the repo. |
| Remediate | `remify/remediate/` | Claude returns a structured plan (verdict, confidence, explanation, exact search/replace edits). Edits are applied locally and must match exactly once, so only fixes that apply cleanly are emitted as a diff. |

Design and research docs:
- [docs/architecture.md](docs/architecture.md): thesis, architecture, risks
- [docs/research/customer-cloud-data-protection.md](docs/research/customer-cloud-data-protection.md): IP protection and output integrity options (high priority)
- [docs/research/integration-frameworks.md](docs/research/integration-frameworks.md): SARIF, CycloneDX/VEX, OSV, DefectDojo (medium priority)

## Roadmap

1. More ingestors: Snyk JSON, Trivy JSON, Gitleaks, Dependabot alerts.
2. Verification loop: re-run the original scanner and the project's tests on the patched tree.
3. SCA/container remediation (version bumps, base-image upgrades).
4. GitHub/GitLab app that opens fix PRs automatically.
5. Split-plane agent for customer-managed deployments; Ed25519/KMS signing.

## Development

```bash
pytest
```
