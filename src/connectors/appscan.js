/**
 * HCL AppScan on Cloud / AppScan 360 (SAST, DAST, SCA, IAST), API v4.
 *
 *   POST /api/v4/Account/ApiKeyLogin         { KeyId, KeySecret } → Token
 *   GET  /api/v4/Apps                        OData $top/$skip, { Items, Count }
 *   GET  /api/v4/Issues/Application/{id}     every issue of one application
 */

import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';

const PAGE = 500;

const KIND_BY_METHOD = { SAST: 'sast', DAST: 'dast', SCA: 'sca', IAST: 'dast', OSSA: 'sca' };
const STATUS = { Fixed: 'fixed', Passed: 'fixed', Noise: 'not-exploitable' };

export function toFinding(issue, { app = {} } = {}) {
  const method = String(issue.DiscoveryMethod ?? issue.Scanner ?? '').toUpperCase();
  const kind = KIND_BY_METHOD[method] ?? 'other';
  const line = Number(issue.Line);
  return makeFinding({
    engine: 'appscan',
    nativeId: issue.Id,
    kind,
    title: issue.IssueType ?? issue.IssueTypeId,
    severity: issue.Severity,
    status: STATUS[issue.Status] ?? 'open',
    cwe: issue.Cwe,
    cve: issue.Cve,
    asset: { project: app.Name ?? issue.ApplicationName, url: kind === 'dast' ? issue.Url ?? issue.Location : null },
    location: kind === 'dast' ? {} : { file: issue.SourceFile ?? issue.Location, line: Number.isInteger(line) ? line : null },
    pkg: { name: issue.LibraryName, version: issue.LibraryVersion, fixedVersion: issue.FixedVersion },
    endpoint: kind === 'dast' ? { url: issue.Url ?? issue.Location, method: issue.HttpMethod, parameter: issue.Element ?? issue.Parameter } : {},
    description: issue.Context ?? null,
    remediation: issue.FixRecommendation ?? issue.Remediation ?? null,
    firstFoundAt: issue.DateCreated,
    lastSeenAt: issue.LastUpdated ?? issue.LastFound,
    raw: issue,
  });
}

export class AppScanConnector extends Connector {
  static id = 'appscan';
  static label = 'AppScan';
  static required = ['keyId', 'keySecret'];

  #token = null;
  #expiresAt = 0;

  get base() {
    return String(this.config.url || 'https://cloud.appscan.com').replace(/\/+$/, '');
  }

  async authHeaders() {
    if (!this.#token || Date.now() >= this.#expiresAt) {
      const answer = await request(this.label, `${this.base}/api/v4/Account/ApiKeyLogin`, {
        method: 'POST',
        body: { KeyId: this.config.keyId, KeySecret: this.config.keySecret },
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.Token) throw new Error('AppScan gave no token for this API key.');
      this.#token = answer.Token;
      const expires = Date.parse(answer.Expire ?? '');
      this.#expiresAt = Number.isFinite(expires) ? expires - 60_000 : Date.now() + 30 * 60_000;
    }
    return { Authorization: `Bearer ${this.#token}` };
  }

  async *items(url, query = {}) {
    for (let skip = 0; ; skip += PAGE) {
      const page = await this.call(url, { query: { ...query, $top: PAGE, $skip: skip, $count: true } });
      const items = page?.Items ?? (Array.isArray(page) ? page : []);
      yield* items;
      if (items.length < PAGE || skip + items.length >= Number(page?.Count ?? Infinity)) return;
    }
  }

  async check() {
    const page = await this.call(`${this.base}/api/v4/Apps`, { query: { $top: 1, $count: true } });
    return `${page?.Count ?? page?.Items?.length ?? 0} applications`;
  }

  async *findings() {
    const wanted = new Set([].concat(this.config.applications ?? []));
    const filter = this.config.includeFixed ? undefined : "Status ne 'Fixed'";
    let count = 0;
    for await (const app of this.items(`${this.base}/api/v4/Apps`)) {
      if (wanted.size && !wanted.has(app.Name) && !wanted.has(app.Id)) continue;
      for await (const issue of this.items(`${this.base}/api/v4/Issues/Application/${encodeURIComponent(app.Id)}`, filter ? { $filter: filter } : {})) {
        yield toFinding(issue, { app });
        if (++count >= this.maxFindings) return;
      }
    }
  }
}
