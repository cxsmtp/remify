import { Connector } from '../connector.js';
import { makeFinding, parseCwe } from '../finding.js';

const PAGE = 200;

export const SCANS_QUERY = `query RemifyScans($offset: Int, $limit: Int) {
  scans(offset: $offset, limit: $limit, scan_status: [succeeded], sort_column: start, sort_order: desc) {
    id site_id site_name end_time
  }
}`;

export const ISSUES_QUERY = `query RemifyIssues($id: ID!, $start: Int!, $count: Int!) {
  scan(id: $id) {
    issues(start: $start, count: $count) {
      serial_number severity confidence path origin novelty
      issue_type { type_index name description_html remediation_html vulnerability_classifications_html references_html }
    }
  }
}`;

const text = (html) => (html ? String(html).replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim() : null);
const links = (html) => [...String(html ?? '').matchAll(/href="([^"]+)"/g)].map((m) => m[1]);

export function toFinding(issue, { scan = {} } = {}) {
  const type = issue.issue_type ?? {};
  const url = `${issue.origin ?? ''}${issue.path ?? ''}` || null;
  return makeFinding({
    engine: 'burp',
    nativeId: `${scan.site_id ?? scan.id}:${issue.serial_number}`,
    kind: 'dast',
    title: type.name,
    severity: issue.severity,
    status: issue.confidence === 'false_positive' ? 'not-exploitable' : 'open',
    cwe: parseCwe(String(type.vulnerability_classifications_html ?? '').match(/CWE-\d+/)?.[0]),
    asset: { project: scan.site_name, url: issue.origin },
    endpoint: { url },
    description: text(type.description_html),
    remediation: text(type.remediation_html),
    references: links(type.references_html),
    lastSeenAt: scan.end_time,
    raw: { ...issue, scanId: scan.id },
  });
}

export class BurpConnector extends Connector {
  static id = 'burp';
  static label = 'Burp Suite DAST';
  static required = ['url', 'apiKey'];

  get endpoint() {
    return `${String(this.config.url).replace(/\/+$/, '')}/graphql/v1`;
  }

  async authHeaders() {
    return { Authorization: this.config.apiKey };
  }

  async graphql(query, variables) {
    const answer = await this.call(this.endpoint, { method: 'POST', body: { query, variables } });
    if (answer?.errors?.length) throw new Error(`Burp Suite DAST: ${answer.errors.map((e) => e.message).join('; ')}`);
    return answer?.data ?? {};
  }

  /** Each site's newest succeeded scan. */
  async latestScans() {
    const bySite = new Map();
    for (let offset = 0; ; offset += PAGE) {
      const scans = (await this.graphql(SCANS_QUERY, { offset, limit: PAGE })).scans ?? [];
      for (const scan of scans) if (!bySite.has(scan.site_id)) bySite.set(scan.site_id, scan);
      if (scans.length < PAGE) return [...bySite.values()];
    }
  }

  async check() {
    const scans = (await this.graphql(SCANS_QUERY, { offset: 0, limit: 1 })).scans ?? [];
    return scans.length ? `latest scan: ${scans[0].site_name}` : 'connected, no succeeded scans yet';
  }

  /** One unit per site's latest scan, several read at once. */
  async units() {
    return (await this.latestScans()).map((scan) => ({ key: scan.id, scan }));
  }

  async *unitFindings({ scan }) {
    for (let start = 0; ; start += PAGE) {
      const issues = (await this.graphql(ISSUES_QUERY, { id: scan.id, start, count: PAGE })).scan?.issues ?? [];
      for (const issue of issues) yield toFinding(issue, { scan });
      if (issues.length < PAGE) return;
    }
  }
}
