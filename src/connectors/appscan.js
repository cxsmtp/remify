import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';
import { countedPages } from '../pool.js';

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

  get base() {
    return String(this.config.url || 'https://cloud.appscan.com').replace(/\/+$/, '');
  }

  async authHeaders() {
    const token = await this.token(async () => {
      const answer = await request(this.label, `${this.base}/api/v4/Account/ApiKeyLogin`, {
        method: 'POST',
        body: { KeyId: this.config.keyId, KeySecret: this.config.keySecret },
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.Token) throw new Error('AppScan gave no token for this API key.');
      const expires = Date.parse(answer.Expire ?? '');
      return { value: answer.Token, expiresInMs: Number.isFinite(expires) ? expires - Date.now() : 30 * 60_000 };
    });
    return { Authorization: `Bearer ${token}` };
  }

  /** Every item of an OData collection: the first page gives Count, the rest are read at once. */
  items(url, query = {}) {
    return countedPages(
      async (skip) => {
        const page = await this.call(url, { query: { ...query, $top: PAGE, $skip: skip, $count: true } });
        return { rows: page?.Items ?? (Array.isArray(page) ? page : []), total: page?.Count };
      },
      { pageSize: PAGE, limit: this.concurrency },
    );
  }

  async check() {
    const page = await this.call(`${this.base}/api/v4/Apps`, { query: { $top: 1, $count: true } });
    return `${page?.Count ?? page?.Items?.length ?? 0} applications`;
  }

  /** One unit per application, several read at once. */
  async units() {
    const wanted = new Set([].concat(this.config.applications ?? []));
    const units = [];
    for await (const app of this.items(`${this.base}/api/v4/Apps`)) {
      if (!wanted.size || wanted.has(app.Name) || wanted.has(app.Id)) units.push({ key: app.Id, app });
    }
    return units;
  }

  async *unitFindings({ app }) {
    const filter = this.config.includeFixed ? undefined : "Status ne 'Fixed'";
    for await (const issue of this.items(`${this.base}/api/v4/Issues/Application/${encodeURIComponent(app.Id)}`, filter ? { $filter: filter } : {})) {
      yield toFinding(issue, { app });
    }
  }
}
