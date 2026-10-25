# Action item: research security tool integration frameworks

Owner: @me · Priority: **Medium** · Source: memo of 25 Oct 2026 (09:15 Asia/Dubai)

**Question:** how do we ingest results from "every tool out there" without
the cost of keeping deep context for each one growing out of control?

## Standards and formats to build on

| Format | Covers | Who emits it | Use in Remify |
|---|---|---|---|
| **SARIF 2.1.0** (OASIS) | SAST, IaC, some secrets | Semgrep, CodeQL, Snyk Code, Checkov, Trivy, GitHub code scanning, Checkmarx export | Primary input. **Done** (`ingest/sarif.py`) |
| **CycloneDX** (incl. VEX) | SBOM, dependency vulnerabilities, exploitability | Trivy, Grype, Snyk, Dependency-Track | SCA input; VEX lets us record "not exploitable" triage verdicts |
| **SPDX** | SBOM | Many build tools | Secondary SBOM input |
| **OSV schema** | Open-source vulnerability records | osv.dev, GitHub Advisory Database | Look up fixed versions for SCA fixes |
| **OCSF** | Normalized security events | AWS Security Lake and others | Possible export target, not core |
| Vendor JSON / APIs | Data SARIF drops (data-flow, triage state) | Checkmarx One, Snyk, SonarQube, Veracode | Thin adapters only where SARIF loses information. Checkmarx **done** |

Existing aggregators such as OWASP DefectDojo already parse well over 100 scanner
formats. Supporting a DefectDojo import (or its parsers as a reference) is a
fast way to gain wide coverage without writing every adapter ourselves.

## Architecture rule (handles the scalability risk)

Keep the core **category-aware, not tool-aware**:

```
many thin tool adapters  ──►  one Finding model  ──►  one strategy per category
(Checkmarx, Snyk, ...)          (models.py)           SAST | SCA | IaC | Secrets | Container
```

Deep context, such as the call graph, framework, dependency versions and
infrastructure state, is built once per **category** from the repository
itself, not per tool. Adding a scanner then costs one adapter
(`detect()` + `parse()`), not a new remediation pipeline.

## Suggested order

1. SARIF (**done**), Checkmarx One (**done**)
2. CycloneDX/VEX: unlocks SCA fixes (version upgrades)
3. Snyk JSON and Trivy JSON: largest install base after Checkmarx
4. Gitleaks/TruffleHog: secret fixes (rotate + move to a secret manager)
5. DefectDojo import: long-tail coverage

## Next steps

- [ ] Add a CycloneDX/VEX ingestor and SCA strategy.
- [ ] Export triage verdicts as VEX / SARIF suppressions so scanners stop re-raising false positives.
- [ ] Evaluate reusing DefectDojo's parsers (confirm its license first; it is published as BSD-3-Clause).
