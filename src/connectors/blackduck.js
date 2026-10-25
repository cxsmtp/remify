import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding, normalizeSeverity, severityFromScore } from '../finding.js';
import { countedPages, mapPool } from '../pool.js';

const PAGE = 100;
const BOM_ACCEPT = 'application/vnd.blackducksoftware.bill-of-materials-6+json';

const STATUS = {
  IGNORED: 'accepted',
  MITIGATED: 'accepted',
  PATCHED: 'fixed',
  REMEDIATION_COMPLETE: 'fixed',
  DUPLICATE: 'accepted',
};

/** One vulnerable-bom-components row as a finding. */
export function toFinding(row, { project = {}, version = {} } = {}) {
  const vuln = row.vulnerabilityWithRemediation ?? {};
  const name = vuln.vulnerabilityName ?? '';
  return makeFinding({
    engine: 'blackduck',
    nativeId: `${version._meta?.href ?? version.versionName ?? 'version'}|${row.componentVersion ?? row.componentName}|${name}`,
    kind: 'sca',
    title: `${name} in ${row.componentName} ${row.componentVersionName ?? ''}`.trim(),
    severity: vuln.severity ? normalizeSeverity(vuln.severity) : severityFromScore(vuln.overallScore ?? vuln.baseScore),
    status: STATUS[vuln.remediationStatus] ?? 'open',
    cwe: vuln.cweId,
    cve: name.startsWith('CVE-') ? name : vuln.relatedVulnerability,
    asset: { project: project.name, branch: version.versionName },
    pkg: { name: row.componentName, version: row.componentVersionName, ecosystem: row.componentVersionOriginName ?? row.originName },
    description: vuln.description,
    remediation: vuln.remediationComment ?? null,
    references: [vuln._meta?.href, vuln.relatedVulnerability].filter(Boolean),
    firstFoundAt: vuln.vulnerabilityPublishedDate,
    lastSeenAt: vuln.vulnerabilityUpdatedDate ?? vuln.remediationUpdatedAt,
    raw: row,
  });
}

export class BlackDuckConnector extends Connector {
  static id = 'blackduck';
  static label = 'Black Duck';
  static required = ['url', 'token'];

  get base() {
    return String(this.config.url).replace(/\/+$/, '');
  }

  async authHeaders() {
    const bearer = await this.token(async () => {
      const answer = await request(this.label, `${this.base}/api/tokens/authenticate`, {
        method: 'POST',
        headers: { Authorization: `token ${this.config.token}`, Accept: 'application/vnd.blackducksoftware.user-4+json' },
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.bearerToken) throw new Error('Black Duck gave no bearer token for this API token.');
      return { value: answer.bearerToken, expiresInMs: Number(answer.expiresInMilliseconds ?? 3_600_000) };
    });
    return { Authorization: `Bearer ${bearer}` };
  }

  /** Every item of a collection: the first page gives totalCount, the rest are read at once. */
  items(url, accept) {
    return countedPages(
      async (offset) => {
        const page = await this.call(url, { query: { offset, limit: PAGE }, headers: accept ? { Accept: accept } : {} });
        return { rows: page?.items ?? [], total: page?.totalCount };
      },
      { pageSize: PAGE, limit: this.concurrency },
    );
  }

  async check() {
    const page = await this.call(`${this.base}/api/projects`, { query: { offset: 0, limit: 1 } });
    return `${page?.totalCount ?? 0} projects`;
  }

  /** One unit per project version, its projects' versions listed at once. */
  async units() {
    const wanted = new Set([].concat(this.config.projects ?? []));
    const projects = [];
    for await (const project of this.items(`${this.base}/api/projects`)) {
      if (!wanted.size || wanted.has(project.name)) projects.push(project);
    }
    const perProject = await mapPool(projects, this.concurrency, async (project) => {
      const versions = [];
      for await (const version of this.items(`${project._meta.href}/versions`)) versions.push(version);
      if (this.config.latestVersionOnly) versions.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).splice(1);
      return versions.map((version) => ({ key: version._meta.href, project, version }));
    });
    return perProject.flat();
  }

  async *unitFindings({ project, version }) {
    for await (const row of this.items(`${version._meta.href}/vulnerable-bom-components`, BOM_ACCEPT)) {
      yield toFinding(row, { project, version });
    }
  }
}
