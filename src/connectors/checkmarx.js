/**
 * Checkmarx One: SAST, SCA, IaC (KICS), containers and secrets, from each
 * project's latest completed scan.
 *
 * The API key is a JWT whose `iss` claim names the tenant's realm (e.g.
 * https://eu.iam.checkmarx.net/auth/realms/acme), so the key alone gives the
 * IAM host, the tenant and the API host (iam → ast). It is exchanged for an
 * access token with the refresh-token grant and the public `ast-app` client,
 * as Mission Zero does.
 *
 *   GET /api/projects                       offset/limit, { projects, totalCount }
 *   GET /api/projects/last-scan             { [projectId]: scan }
 *   GET /api/results/?scan-id=              offset is a PAGE number; a short page ends it
 *
 * Checkmarx One runs AI Triage (1 credit) and AI Remediation (3 credits) itself.
 */

import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';

const ACCEPT = 'application/json; version=1.0';
const PROJECT_PAGE = 100;
const RESULTS_PAGE = 200;
const LAST_SCAN_CHUNK = 50;
const EXPIRY_SKEW_MS = 30_000;

/** The routing claims of an API key; null when it is not a JWT. */
export function decodeApiKey(apiKey) {
  const payload = String(apiKey ?? '').trim().split('.')[1];
  if (!payload) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/** IAM URL, tenant, API URL and token URL from the key, each overridable for single-tenant deployments. */
export function deriveConnection(apiKey, { iamUrl, tenant, apiUrl } = {}) {
  const issuer = decodeApiKey(apiKey)?.iss ?? '';
  const match = String(issuer).match(/^(https?:\/\/[^/]+)\/auth\/realms\/([^/?#]+)/);
  const iam = (iamUrl || match?.[1] || '').replace(/\/+$/, '');
  const realm = tenant || (match ? decodeURIComponent(match[2]) : '');
  if (!iam || !realm) throw new Error('The Checkmarx One API key does not name its tenant: paste the whole key, or set iamUrl and tenant.');
  let api = apiUrl;
  if (!api) {
    const url = new URL(iam);
    api = `${url.protocol}//${url.host.replace(/^iam\./i, 'ast.').replace(/\.iam\./i, '.ast.')}`;
  }
  return {
    iamUrl: iam,
    tenant: realm,
    apiUrl: api.replace(/\/+$/, ''),
    tokenUrl: `${iam}/auth/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`,
  };
}

const KIND_BY_TYPE = {
  sast: 'sast',
  sca: 'sca',
  kics: 'iac',
  containers: 'container',
  'sscs-secret-detection': 'secret',
};

/** "Npm-lodash-4.17.20" → { ecosystem: 'npm', name: 'lodash', version: '4.17.20' }. */
export function parsePackageIdentifier(identifier) {
  const parts = String(identifier ?? '').split('-');
  if (parts.length < 3) return { name: identifier || null, version: null, ecosystem: null };
  return { ecosystem: parts[0].toLowerCase(), name: parts.slice(1, -1).join('-'), version: parts.at(-1) };
}

const STATUS_BY_STATE = {
  NOT_EXPLOITABLE: 'not-exploitable',
  PROPOSED_NOT_EXPLOITABLE: 'not-exploitable',
};

/** One GET /api/results row as a finding. */
export function toFinding(row, { project = {}, scan = {} } = {}) {
  const data = row.data ?? {};
  const details = row.vulnerabilityDetails ?? {};
  const kind = KIND_BY_TYPE[row.type] ?? 'other';
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const dataFlow = nodes.map((node) => ({ file: node.fileName, line: node.line, column: node.column, method: node.method, name: node.name }));
  const pkg = kind === 'sca' ? { ...parsePackageIdentifier(data.packageIdentifier), fixedVersion: data.recommendedVersion }
    : kind === 'container' ? { name: data.packageName, version: data.packageVersion, fixedVersion: data.recommendedVersion }
    : {};
  if (kind === 'sca' && data.packageName) pkg.name = data.packageName;

  const title = data.queryName || data.ruleName || details.cveName || (pkg.name ? `${pkg.name} ${pkg.version ?? ''}`.trim() : '') || row.type;
  const remediation = [data.remediation, data.remediationAdditional].filter(Boolean).join(' ') ||
    (pkg.fixedVersion ? `Upgrade ${pkg.name} to ${pkg.fixedVersion}.` : '') ||
    (data.expectedValue ? `Expected: ${data.expectedValue}. Found: ${data.actualValue ?? 'something else'}.` : '');

  return makeFinding({
    engine: 'checkmarx',
    nativeId: `${project.id ?? scan.projectId ?? 'project'}:${row.id ?? row.alternateId}`,
    kind,
    title,
    severity: row.severity,
    status: row.status === 'FIXED' ? 'fixed' : STATUS_BY_STATE[row.state] ?? 'open',
    cwe: details.cweId ?? data.cweId,
    cve: details.cveName ?? data.cveName,
    asset: {
      project: project.name,
      repo: project.repoUrl,
      branch: scan.branch,
      image: data.imageName ? `${data.imageName}${data.imageTag ? `:${data.imageTag}` : ''}` : null,
    },
    location: {
      file: nodes[0]?.fileName ?? data.fileName ?? data.filename,
      line: nodes[0]?.line ?? data.line,
      dataFlow,
    },
    pkg,
    description: row.description || data.ruleDescription || data.description,
    remediation,
    references: [data.remediationLink, ...(details.references ?? []).map((ref) => ref?.url ?? ref)].filter((ref) => typeof ref === 'string'),
    firstFoundAt: row.firstFoundAt,
    lastSeenAt: row.foundAt,
    raw: { ...row, scanId: scan.id },
  });
}

export class CheckmarxConnector extends Connector {
  static id = 'checkmarx';
  static label = 'Checkmarx One';
  static required = ['apiKey'];
  static nativeActions = ['triage', 'remediate'];

  #connection = null;
  #token = null;
  #expiresAt = 0;

  get connection() {
    this.#connection ??= deriveConnection(this.config.apiKey, this.config);
    return this.#connection;
  }

  async authHeaders() {
    if (!this.#token || Date.now() >= this.#expiresAt) {
      const answer = await request(this.label, this.connection.tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'ast-app', refresh_token: this.config.apiKey }),
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.access_token) throw new Error('Checkmarx One gave no access token for this API key.');
      this.#token = answer.access_token;
      this.#expiresAt = Date.now() + Number(answer.expires_in ?? 300) * 1000 - EXPIRY_SKEW_MS;
    }
    return { Authorization: `Bearer ${this.#token}`, Accept: ACCEPT };
  }

  api(path) {
    return `${this.connection.apiUrl}${path}`;
  }

  async check() {
    const page = await this.call(this.api('/api/projects'), { query: { offset: 0, limit: 1 } });
    return `tenant ${this.connection.tenant}, ${page?.totalCount ?? page?.projects?.length ?? 0} projects`;
  }

  /** Every project, or only those named in config.projects. */
  async *projects() {
    const wanted = new Set([].concat(this.config.projects ?? []).map(String));
    for (let offset = 0; ; offset += PROJECT_PAGE) {
      const page = await this.call(this.api('/api/projects'), { query: { offset, limit: PROJECT_PAGE } });
      const projects = page?.projects ?? [];
      for (const project of projects) {
        if (wanted.size && !wanted.has(project.name) && !wanted.has(project.id)) continue;
        yield project;
      }
      if (projects.length < PROJECT_PAGE) return;
    }
  }

  async lastScans(projectIds) {
    const scans = {};
    for (let i = 0; i < projectIds.length; i += LAST_SCAN_CHUNK) {
      const ids = projectIds.slice(i, i + LAST_SCAN_CHUNK);
      const answer = await this.call(this.api('/api/projects/last-scan'), { query: { 'project-ids': ids, 'scan-status': 'Completed' } });
      for (const [id, scan] of Object.entries(answer ?? {})) if (scan && typeof scan === 'object') scans[id] = scan;
    }
    return scans;
  }

  async *scanResults(scanId) {
    for (let page = 0; ; page += 1) {
      const answer = await this.call(this.api('/api/results/'), { query: { 'scan-id': scanId, limit: RESULTS_PAGE, offset: page } });
      const rows = answer?.results ?? [];
      yield* rows;
      if (rows.length < RESULTS_PAGE) return;
    }
  }

  async *findings() {
    const projects = [];
    for await (const project of this.projects()) projects.push(project);
    const scans = await this.lastScans(projects.map((p) => p.id));
    const types = new Set([].concat(this.config.engines ?? []));
    let count = 0;
    for (const project of projects) {
      const scan = scans[project.id];
      if (!scan?.id) continue;
      for await (const row of this.scanResults(scan.id)) {
        if (types.size && !types.has(row.type)) continue;
        yield toFinding(row, { project, scan });
        if (++count >= this.maxFindings) return;
      }
    }
  }
}
