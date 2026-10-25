import { Connector } from '../connector.js';
import { makeFinding, parseCwe } from '../finding.js';
import { mapPool } from '../pool.js';

const PAGE = 100;
const SEVERITY = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };
const STATUS = { fixed: 'fixed', ignored: 'accepted', false_positive: 'not-exploitable' };

export function toFinding(vuln, details = {}) {
  const tags = [].concat(vuln.tags ?? details.tags ?? []);
  return makeFinding({
    engine: 'acunetix',
    nativeId: vuln.vuln_id,
    kind: 'dast',
    title: vuln.vt_name,
    severity: SEVERITY[vuln.severity] ?? 'info',
    status: STATUS[vuln.status] ?? 'open',
    cwe: parseCwe(tags.find((t) => /^CWE-/i.test(t))),
    cve: tags.find((t) => /^CVE-/i.test(t)) ?? null,
    asset: { project: vuln.target_description ?? vuln.target_id, url: vuln.affects_url },
    endpoint: { url: vuln.affects_url, parameter: vuln.affects_detail },
    description: details.description ?? null,
    remediation: details.recommendation ?? null,
    references: (details.references ?? []).map((r) => r.href ?? r).filter((r) => typeof r === 'string'),
    lastSeenAt: vuln.last_seen,
    raw: { ...vuln, details: Object.keys(details).length ? details : undefined },
  });
}

export class AcunetixConnector extends Connector {
  static id = 'acunetix';
  static label = 'Acunetix';
  static required = ['url', 'apiKey'];

  get base() {
    return `${String(this.config.url).replace(/\/+$/, '')}/api/v1`;
  }

  async authHeaders() {
    return { 'X-Auth': this.config.apiKey };
  }

  async check() {
    const me = await this.call(`${this.base}/me`);
    return me?.email ? `signed in as ${me.email}` : 'key accepted';
  }

  /** One cursor walk, one unit; with withDetails, each page's details are read at once. */
  async *unitFindings() {
    const q = this.config.includeClosed ? undefined : 'status:open';
    let cursor;
    for (;;) {
      const page = await this.call(`${this.base}/vulnerabilities`, { query: { l: PAGE, c: cursor, q } });
      const vulns = page?.vulnerabilities ?? [];
      const details = this.config.withDetails
        ? await mapPool(vulns, this.concurrency, async (vuln) => (await this.call(`${this.base}/vulnerabilities/${encodeURIComponent(vuln.vuln_id)}`)) ?? {})
        : [];
      for (const [i, vuln] of vulns.entries()) yield toFinding(vuln, details[i] ?? {});
      cursor = page?.pagination?.next_cursor;
      if (!cursor) return;
    }
  }
}
