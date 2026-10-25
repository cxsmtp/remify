import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';
import { countedPages, mapPool, numberedPages } from '../pool.js';

const ACCEPT = 'application/json; version=1.0';
const PROJECT_PAGE = 100;
const RESULTS_PAGE = 200;
const LAST_SCAN_CHUNK = 50;
// Result pages of one scan asked for at once.
const RESULTS_AHEAD = 4;
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

  get connection() {
    this.#connection ??= deriveConnection(this.config.apiKey, this.config);
    return this.#connection;
  }

  async authHeaders() {
    const token = await this.token(async () => {
      const answer = await request(this.label, this.connection.tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'ast-app', refresh_token: this.config.apiKey }),
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.access_token) throw new Error('Checkmarx One gave no access token for this API key.');
      return { value: answer.access_token, expiresInMs: Number(answer.expires_in ?? 300) * 1000 + 60_000 - EXPIRY_SKEW_MS };
    });
    return { Authorization: `Bearer ${token}`, Accept: ACCEPT };
  }

  api(path) {
    return `${this.connection.apiUrl}${path}`;
  }

  async check() {
    const page = await this.call(this.api('/api/projects'), { query: { offset: 0, limit: 1 } });
    return `tenant ${this.connection.tenant}, ${page?.totalCount ?? page?.projects?.length ?? 0} projects`;
  }

  /** Every project, or only those named in config.projects: the first page gives the total, the rest are read at once. */
  async projects() {
    const wanted = new Set([].concat(this.config.projects ?? []).map(String));
    const projects = [];
    const pages = countedPages(
      async (offset) => {
        const page = await this.call(this.api('/api/projects'), { query: { offset, limit: PROJECT_PAGE } });
        return { rows: page?.projects ?? [], total: page?.filteredTotalCount ?? page?.totalCount };
      },
      { pageSize: PROJECT_PAGE, limit: this.concurrency },
    );
    for await (const project of pages) {
      if (wanted.size && !wanted.has(project.name) && !wanted.has(project.id)) continue;
      projects.push(project);
    }
    return projects;
  }

  /** Each project's latest completed scan, chunks of project ids asked for at once. */
  async lastScans(projectIds) {
    const chunks = [];
    for (let i = 0; i < projectIds.length; i += LAST_SCAN_CHUNK) chunks.push(projectIds.slice(i, i + LAST_SCAN_CHUNK));
    const answers = await mapPool(chunks, this.concurrency, (ids) =>
      this.call(this.api('/api/projects/last-scan'), { query: { 'project-ids': ids, 'scan-status': 'Completed' } }),
    );
    const scans = {};
    for (const answer of answers) {
      for (const [id, scan] of Object.entries(answer ?? {})) if (scan && typeof scan === 'object') scans[id] = scan;
    }
    return scans;
  }

  /** One unit per project with a completed scan, keyed by its scan: a new scan is a new unit. */
  async units() {
    const projects = await this.projects();
    const scans = await this.lastScans(projects.map((p) => p.id));
    return projects.filter((p) => scans[p.id]?.id).map((project) => ({ key: `${project.id}:${scans[project.id].id}`, project, scan: scans[project.id] }));
  }

  async *unitFindings({ project, scan }) {
    const types = new Set([].concat(this.config.engines ?? []));
    // /api/results numbers pages rather than rows and its totalCount is not reliable: pages are read a few ahead.
    const rows = numberedPages(
      async (page) => (await this.call(this.api('/api/results/'), { query: { 'scan-id': scan.id, limit: RESULTS_PAGE, offset: page } }))?.results ?? [],
      { pageSize: RESULTS_PAGE, ahead: RESULTS_AHEAD },
    );
    for await (const row of rows) {
      if (types.size && !types.has(row.type)) continue;
      yield toFinding(row, { project, scan });
    }
  }
}
