# remify

**One command center over every AppSec engine.** Checkmarx, Snyk, Black Duck, Mend.io, Wiz, Aikido, AppScan, Burp Suite DAST, Acunetix and more keep doing what they are best at: finding the gaps. remify connects to all of them in one go, reads every finding through their APIs into one shape, merges the same gap reported by several engines, and then triages and fixes it, and keeps it fixed.

It replaces no engine. It is the layer above them, built on the frame of [CxMissionZero](https://github.com/cxsmtp/CxDetectionDateBaseReminder), which does this for Checkmarx One alone.

## How it works

| Layer | What it does | Status |
| --- | --- | --- |
| **1. Fetch** | One config connects every engine at once. Each connector reads everything its API gives, every page, into one finding shape: kind, severity, CWE/CVE, file and line with the data flow, package and fixed version, endpoint, the engine's own fix advice, and the raw row. Duplicates are merged across engines. | **This release** |
| **2. Make sense** | An AI agent gathers each issue's full context (the code at every data-flow line, the dependency path, the resource) and analyses it before anything is trusted, the way FAE Flush clears false positives in Mission Zero: a verdict (not exploitable, acceptable risk, action required) with its reasons. | Next |
| **3. Act** | Remediation advice and the fix as a patch or pull request, then a rescan to prove it is gone, and governance that keeps it at zero. | After |

**Fixed cost per action.** Triage costs 1 credit and remediation 3, whichever engine found the gap. Where the engine has its own AI (Checkmarx One AI Triage and Remediation), the customer can spend their credits there; everywhere else remify does it with its own. Each connector declares what its vendor can do natively (`nativeActions`).

**Merging.** The same gap, reported many times, is triaged and fixed once. Two findings are the same gap when they share:

| Kind | Key |
| --- | --- |
| Code (SAST) | file + line + CWE |
| Secret, IaC | file + line |
| Package (SCA, container) | package + version + CVE |
| DAST | host + path + parameter + CWE |
| Cloud | resource + CVE or rule |

Engines name repositories differently, so findings that match are kept apart only when both name a repository and the names differ. An issue more than one engine reports is marked *corroborated*. On one real Checkmarx scan, 10 of 16 criticals were one line reported ten times: one triage credit instead of ten.

## Engines

| Engine | Reads | Tried against |
| --- | --- | --- |
| Checkmarx One | SAST, SCA, IaC (KICS), containers, secrets, from each project's latest scan | real finding shapes from a live tenant |
| Snyk | Open Source, Code, Container, IaC issues (REST API, every org) | documented API, sample answers |
| Black Duck | vulnerable BOM components of every project version | documented API, sample answers |
| Mend.io | dependency security findings (API 3.0) | documented API, sample answers |
| Wiz | vulnerability findings and issues (GraphQL) | documented API, sample answers |
| Aikido | every issue type, from the issues export | documented API, sample answers |
| AppScan (on Cloud / 360) | SAST, DAST, SCA, IAST issues of every application (API v4) | documented API, sample answers |
| Burp Suite DAST | issues of each site's latest scan (GraphQL) | documented API, sample answers |
| Acunetix | vulnerabilities, with details when `withDetails` (API v1) | documented API, sample answers |

Each engine will be checked against a live account one by one; until then, expect a field name or a page parameter to need a fix on first contact. Adding an engine is one file in `src/connectors/` and one line in `src/engines.js`.

## Run it

Node.js 20 or later; nothing to install.

```sh
cp remify.config.example.json remify.config.json   # keep only the engines you use
export CX_API_KEY=… SNYK_TOKEN=…                   # secrets stay in the environment
node src/cli.js connect                            # checks every engine at once
node src/cli.js fetch --out findings.json          # every finding, merged into issues
```

`fetch` prints, per engine, how many findings it read (or why it stopped; the others carry on), then how many issues they merge into and how many more than one engine confirms. `--engines checkmarx,snyk` reads only those, `--max 500` caps each engine while trying it out.

```sh
npm test
```

## Layout

```
src/finding.js        the one finding shape, severities, CWE/CVE parsing
src/connector.js      what every connector is
src/connectors/*.js   one per engine
src/engines.js        the list of engines
src/config.js         remify.config.json, ${ENV} secrets
src/run.js            connect all, fetch all, in parallel
src/merge.js          the same gap from many engines → one issue
src/cli.js            remify connect | fetch
```
