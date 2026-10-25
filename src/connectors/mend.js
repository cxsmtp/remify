/**
 * Mend.io (SCA): security findings of every project's dependencies, API 3.0.
 *
 *   POST /api/v3.0/login                     { email, userKey, orgUuid } → refreshToken
 *   POST /api/v3.0/login/accessToken         `wss-refresh-token` → jwtToken
 *   GET  /api/v3.0/orgs/{orgUuid}/projects
 *   GET  /api/v3.0/projects/{uuid}/dependencies/findings/security
 *
 * Pages follow additionalData.paging.next when the answer gives it, else a
 * numeric cursor until a short page. Mend SAST (code findings) is not read yet.
 */

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

  #jwt = null;
  #expiresAt = 0;

  get base() {
    return String(this.config.url || 'https://api-saas.mend.io').replace(/\/+$/, '');
  }

  async authHeaders() {
    if (!this.#jwt || Date.now() >= this.#expiresAt) {
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
      this.#jwt = access.retVal.jwtToken;
      this.#expiresAt = Date.now() + Number(access.retVal.jwtTTL ?? 1_800_000) - 60_000;
    }
    return { Authorization: `Bearer ${this.#jwt}` };
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

  async *findings() {
    const wanted = new Set([].concat(this.config.projects ?? []));
    let count = 0;
    for await (const project of this.pages(`${this.base}/api/v3.0/orgs/${encodeURIComponent(this.config.orgUuid)}/projects`)) {
      if (wanted.size && !wanted.has(project.name) && !wanted.has(project.uuid)) continue;
      for await (const row of this.pages(`${this.base}/api/v3.0/projects/${encodeURIComponent(project.uuid)}/dependencies/findings/security`)) {
        yield toFinding(row, { project });
        if (++count >= this.maxFindings) return;
      }
    }
  }
}
