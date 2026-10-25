# Remify architecture and deployment

Origin: voice memo "AI Triage and Remediation Ideas", 25 Oct 2026. The idea:
take what Checkmarx does for triage and remediation, make it work for **every**
security tool, make it understand context so it actually fixes the problem, and
run it either in our cloud or in the customer's environment, while protecting it.

## 1. Tool agnosticism

- One internal model (`Finding`): tool, rule, CWE, severity, location, message.
- SARIF 2.1.0 is the default import format; most modern scanners export it.
- Vendor-specific adapters only where SARIF loses information (e.g. Checkmarx
  data-flow nodes, so we fix at the sink).
- Cross-tool fingerprinting (path + line + CWE) lets agreement between tools
  raise confidence and stops the same issue being fixed twice.

**Scaling risk:** deep context differs per tool and per category (SAST vs SCA vs
IaC vs secrets). Keep the core category-aware rather than tool-aware: one
remediation strategy per *category*, many thin adapters per *tool*.

## 2. Contextual remediation

1. Build context: the file, a window around the finding, and later the call
   graph, framework and dependency versions.
2. Ask the model for a structured plan: verdict (`true_positive` /
   `false_positive` / `needs_human`), confidence, explanation, exact edits.
3. Verify deterministically: edits must apply exactly once. Next steps: re-run
   the scanner on the patched file, then the project's tests.
4. Only verified fixes are emitted; everything else goes back as a triage note.

The "definitive" part comes from step 3, not from the model: a fix is only
shipped once the tooling has shown it applies cleanly, clears the finding and
keeps the tests green.

## 3. Deployment models

| | SaaS (Remify cloud) | Customer-managed |
|---|---|---|
| Code leaves customer | Yes (snippets + finding) | No |
| Model access | Our Anthropic account | Customer's Claude API account, Amazon Bedrock, Google Vertex AI or Microsoft Foundry |
| Our IP exposure | None, logic stays on our servers | High, the main risk |
| Best for | SMB, fast onboarding | Regulated / air-gapped-ish enterprises |

The `Remediator` protocol is the seam: SaaS uses `ClaudeRemediator` directly;
customer-managed swaps in a client for the customer's model endpoint.

## 4. Protecting IP in customer-managed deployments

Ordered from strongest to weakest:

1. **Split architecture (recommended):** the customer runs only a thin *agent*
   (ingest, context building, patch application, verification). The prompt
   library, ranking logic and remediation strategies stay in a Remify control
   plane. Only the minimal code snippet crosses the boundary, under the
   customer's data controls. Most of the value never ships to the customer.
2. **Confidential computing:** run the engine inside attested enclaves
   (AWS Nitro Enclaves, Azure / GCP Confidential VMs). Neither the customer nor
   us can read memory; our image only gets its decryption key after remote attestation.
3. **Signed, licensed containers:** hardened images, license-key checks with
   periodic call-home, prompts/strategies encrypted at rest and decrypted only
   in memory. This deters casual copying but won't stop a determined insider.
4. **Contractual:** EULA terms against reverse engineering, plus audit rights.

Integrity of output (so customers can trust the fix): sign each remediation
result (finding hash + diff hash + engine version) so it can be verified in
CI before merge.

## 5. Open questions

- Pricing: per repo, per fixed finding, or per seat?
- Which second tool to support after Checkmarx (Snyk vs Semgrep vs CodeQL)?
- Minimum verification bar before auto-opening a PR vs. suggesting only.
