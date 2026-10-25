/**
 * Acunetix (DAST), API v1.
 *
 *   GET {url}/api/v1/me                      proves the key (`X-Auth`)
 *   GET {url}/api/v1/vulnerabilities         cursor pages (pagination.next_cursor), open ones unless includeClosed
 *   GET {url}/api/v1/vulnerabilities/{id}    description, impact, recommendation, request: read when withDetails
 *
 * Acunetix severities are numbers: 4 critical, 3 high, 2 medium, 1 low, 0 info.
 */

import { Connector } from '../connector.js';
import { makeFinding, parseCwe } from '../finding.js';

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

  async *findings() {
    const q = this.config.includeClosed ? undefined : 'status:open';
    let cursor;
    let count = 0;
    for (;;) {
      const page = await this.call(`${this.base}/vulnerabilities`, { query: { l: PAGE, c: cursor, q } });
      for (const vuln of page?.vulnerabilities ?? []) {
        const details = this.config.withDetails ? (await this.call(`${this.base}/vulnerabilities/${encodeURIComponent(vuln.vuln_id)}`)) ?? {} : {};
        yield toFinding(vuln, details);
        if (++count >= this.maxFindings) return;
      }
      cursor = page?.pagination?.next_cursor;
      if (!cursor) return;
    }
  }
}
