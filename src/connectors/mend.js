import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding, normalizeSeverity, severityFromScore } from '../finding.js';

const PAGE = 1000;

/** One dependency security finding as a finding. */
export function toFinding(row, { project = {} } = {}) {
  const vuln = row.vulnerability ?? {};
  const component = row.component ?? {};
  const fix = row.topFix ?? {};
  const info = row.findingInfo ?? {};
  return makeFinding({
    engine: 'mend',
    nativeId: row.uuid ?? `${project.uuid}|${component.uuid}|${vuln.name}`,
    kind: 'sca',
    title: `${vuln.name ?? row.name} in ${component.name ?? component.artifactId ?? 'a dependency'}`,
    severity: vuln.severity ? normalizeSeverity(vuln.severity) : severityFromScore(vuln.score),
    status: info.status === 'IGNORED' ? 'accepted' : 'open',
    cve: vuln.name ?? row.name,
    asset: { project: project.name ?? row.project?.name },
    location: { file: component.path },
    pkg: {
      name: component.artifactId ?? component.name,
      version: component.version,
      fixedVersion: fix.fixResolution,
      ecosystem: component.libraryType,
    },
    description: vuln.description,
    remediation: [fix.message, fix.fixResolution].filter(Boolean).join(': ') || null,
    references: [fix.url].filter(Boolean),
    firstFoundAt: info.detectedAt,
    lastSeenAt: info.modifiedAt,
    raw: row,
  });
}

export class MendConnector extends Connector {
  static id = 'mend';
  static label = 'Mend.io';
  static required = ['email', 'userKey', 'orgUuid'];

  get base() {
    return String(this.config.url || 'https://api-saas.mend.io').replace(/\/+$/, '');
  }

  async authHeaders() {
    const jwt = await this.token(async () => {
      const login = await request(this.label, `${this.base}/api/v3.0/login`, {
        method: 'POST',
        body: { email: this.config.email, userKey: this.config.userKey, orgUuid: this.config.orgUuid },
        fetchImpl: this.fetchImpl,
      });
      const refreshToken = login?.retVal?.refreshToken;
      if (!refreshToken) throw new Error('Mend.io gave no refresh token for this email and user key.');
      const access = await request(this.label, `${this.base}/api/v3.0/login/accessToken`, {
        method: 'POST',
        headers: { 'wss-refresh-token': refreshToken },
        fetchImpl: this.fetchImpl,
      });
      if (!access?.retVal?.jwtToken) throw new Error('Mend.io gave no access token.');
      return { value: access.retVal.jwtToken, expiresInMs: Number(access.retVal.jwtTTL ?? 1_800_000) };
    });
    return { Authorization: `Bearer ${jwt}` };
  }

  async *pages(url) {
    let next = url;
    let cursor = 0;
    while (next) {
      const page = await this.call(next, next === url || cursor ? { query: { limit: PAGE, cursor } } : {});
      const rows = page?.retVal ?? [];
      yield* rows;
      const link = page?.additionalData?.paging?.next;
      if (link) {
        next = /^https?:/.test(link) ? link : `${this.base}${link}`;
        cursor = 0;
      } else if (rows.length < PAGE) {
        return;
      } else {
        next = url;
        cursor += 1;
      }
    }
  }

  async check() {
    const page = await this.call(`${this.base}/api/v3.0/orgs/${encodeURIComponent(this.config.orgUuid)}/projects`, { query: { limit: 1 } });
    return `org ${this.config.orgUuid}, ${page?.additionalData?.totalItems ?? page?.retVal?.length ?? 0} projects`;
  }

  /** One unit per project, several read at once. */
  async units() {
    const wanted = new Set([].concat(this.config.projects ?? []));
    const units = [];
    for await (const project of this.pages(`${this.base}/api/v3.0/orgs/${encodeURIComponent(this.config.orgUuid)}/projects`)) {
      if (!wanted.size || wanted.has(project.name) || wanted.has(project.uuid)) units.push({ key: project.uuid, project });
    }
    return units;
  }

  async *unitFindings({ project }) {
    for await (const row of this.pages(`${this.base}/api/v3.0/projects/${encodeURIComponent(project.uuid)}/dependencies/findings/security`)) {
      yield toFinding(row, { project });
    }
  }
}
