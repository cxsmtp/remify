# Remify architecture

Source: voice memo "AI Triage and Remediation Ideas", Sun 25 Oct 2026,
09:15–09:16 (Asia/Dubai).

## Core thesis

A universal **Read & Remediation** engine that goes beyond any single tool
such as Checkmarx: a tool-agnostic, AI-driven layer that understands the
context of each vulnerability and **solves** it, instead of flagging it for
manual review.

## System architecture

```
Security tool inputs ──► Contextual intelligence layer ──► Automated remediation ──┬─► SaaS (proprietary cloud)
 SARIF, Checkmarx, …      normalize · dedupe · context      plan · edit · verify   └─► Customer-managed environment
```

| Stage | Code | Responsibility |
|---|---|---|
| Security tool inputs | `src/remify/ingest/` | One adapter per format → common `Finding` (`models.py`) |
| Contextual intelligence layer | `triage.py`, `context.py` | Cross-tool dedupe and ranking. Code context around each finding. |
| Automated remediation | `remediate/engine.py` | Claude returns a verdict, confidence and exact edits. Edits are applied and checked; only clean fixes are emitted. |
| Deployment | `deploy.py` | `saas` (Remify's Claude account) or customer-managed `bedrock` / `vertex` / `foundry` |
| Output integrity | `integrity.py`, `remify verify` | Signed fixes; CI rejects anything altered |

## Supporting logic → implementation

- **Tool agnosticism:** SARIF covers most scanners. Vendor adapters only where
  SARIF loses information (Checkmarx data-flow sink). See
  [research/integration-frameworks.md](research/integration-frameworks.md).
- **Contextual remediation:** the model sees the whole file plus a focused
  window. It may answer `false_positive` or `needs_human`. "Definitive" comes
  from deterministic checks: exact unique edits now; re-scan and tests next.
- **Flexible deployment:** the same container image runs in every mode,
  selected by `REMIFY_DEPLOYMENT`. In the customer-managed modes, code only
  goes to the customer's own model endpoint.

## Blind spots & strategic risks

| Risk | Mitigation | Status |
|---|---|---|
| **IP protection** in customer infrastructure | Split plane: strategy library stays in Remify cloud. Enclaves for the strictest tier. | Evaluated in [research/customer-cloud-data-protection.md](research/customer-cloud-data-protection.md) |
| **Customer-side security / output integrity** | Every fix signed (finding + diff hash + engine version), checked by `remify verify` | HMAC implemented; Ed25519 + KMS planned |
| **Integration scalability** | Core is category-aware, not tool-aware; thin adapters; standard formats | SARIF + Checkmarx done; CycloneDX next |

## Action items

- [ ] Evaluate customer-cloud data protection models (@me · **high**) → first pass done, see research doc
- [ ] Research security tool integration frameworks (@me · **medium**) → first pass done, see research doc

## Open questions

- Pricing: per repo, per fixed finding, or per seat?
- Which tool to support after Checkmarx: Snyk, Semgrep or CodeQL?
- Minimum verification bar before auto-opening a PR vs. only suggesting.
