/**
 * Snyk: Open Source (SCA), Code (SAST), Container and IaC issues, through the
 * REST API's org-wide issues list.
 *
 *   GET /rest/self                           proves the token
 *   GET /rest/orgs                           every org the token sees (when none is configured)
 *   GET /rest/orgs/{orgId}/issues            JSON:API, cursor pages through links.next
 *
 * Token: a Snyk API token or service-account token, sent as `Authorization: token …`.
 * Region: us (api.snyk.io), eu (api.eu.snyk.io), au (api.au.snyk.io), or apiUrl.
 */

import { Connector } from '../connector.js';
import { makeFinding } from '../finding.js';

const VERSION = '2024-10-15';
const PAGE = 100;
const HOSTS = { us: 'https://api.snyk.io', eu: 'https://api.eu.snyk.io', au: 'https://api.au.snyk.io' };

const KIND_BY_TYPE = {
  package_vulnerability: 'sca',
  license: 'sca',
  code: 'sast',
  cloud: 'cloud',
  config: 'iac',
  custom: 'other',
};

/** One JSON:API issue as a finding. */
export function toFinding(issue, { orgId } = {}) {
  const a = issue.attributes ?? {};
  const coordinates = a.coordinates ?? [];
  const reps = coordinates.flatMap((c) => c.representations ?? []);
  const dependency = reps.find((r) => r.dependency)?.dependency ?? {};
  const source = reps.find((r) => r.sourceLocation)?.sourceLocation ?? null;
  const resource = reps.find((r) => r.resourcePath)?.resourcePath ?? reps.find((r) => r.cloud_resource)?.cloud_resource?.resource?.native_id ?? null;
  const remedies = coordinates.flatMap((c) => c.remedies ?? []);
  const upgrade = remedies.map((r) => r.details?.upgrade_package).find(Boolean);
  const problems = a.problems ?? [];
  const classes = a.classes ?? [];
  const kind = a.type === 'package_vulnerability' && /docker|container|image/i.test(String(issue.relationships?.scan_item?.data?.type ?? ''))
    ? 'container'
    : KIND_BY_TYPE[a.type] ?? 'other';

  return makeFinding({
    engine: 'snyk',
    nativeId: issue.id,
    kind,
    title: a.title,
    severity: a.effective_severity_level,
    status: a.ignored ? 'accepted' : a.status === 'resolved' ? 'fixed' : 'open',
    cwe: classes.find((c) => /cwe/i.test(c.source ?? c.id))?.id,
    cve: problems.map((p) => p.id).find((id) => /^CVE-/i.test(id)),
    asset: { project: issue.relationships?.scan_item?.data?.id, resource },
    location: {
      file: source?.file,
      line: source?.region?.start?.line,
    },
    pkg: { name: dependency.package_name, version: dependency.package_version, fixedVersion: upgrade },
    description: a.description,
    remediation: remedies.map((r) => r.description).filter(Boolean).join(' ') || null,
    references: problems.map((p) => p.url).filter(Boolean),
    firstFoundAt: a.created_at,
    lastSeenAt: a.updated_at,
    raw: { ...issue, orgId },
  });
}

export class SnykConnector extends Connector {
  static id = 'snyk';
  static label = 'Snyk';
  static required = ['token'];

  get base() {
    return (this.config.apiUrl || HOSTS[this.config.region ?? 'us'] || HOSTS.us).replace(/\/+$/, '');
  }

  async authHeaders() {
    return { Authorization: `token ${this.config.token}`, Accept: 'application/vnd.api+json' };
  }

  async check() {
    const self = await this.call(`${this.base}/rest/self`, { query: { version: VERSION } });
    const orgs = await this.orgIds();
    return `${self?.data?.attributes?.name ?? self?.data?.attributes?.username ?? 'token ok'}, ${orgs.length} org(s)`;
  }

  async orgIds() {
    const configured = [].concat(this.config.orgIds ?? this.config.orgId ?? []).filter(Boolean);
    if (configured.length) return configured;
    const ids = [];
    for await (const org of this.pages(`${this.base}/rest/orgs`)) ids.push(org.id);
    return ids;
  }

  /** Every item of a JSON:API collection, following links.next. */
  async *pages(url) {
    let next = url;
    let query = { version: VERSION, limit: PAGE };
    while (next) {
      const page = await this.call(next, { query });
      yield* page?.data ?? [];
      const link = page?.links?.next;
      if (!link) return;
      // links.next is relative and already carries the version and cursor.
      next = /^https?:/.test(link) ? link : `${this.base}${link.startsWith('/rest') ? '' : '/rest'}${link}`;
      query = undefined;
    }
  }

  async *findings() {
    let count = 0;
    for (const orgId of await this.orgIds()) {
      for await (const issue of this.pages(`${this.base}/rest/orgs/${encodeURIComponent(orgId)}/issues`)) {
        yield toFinding(issue, { orgId });
        if (++count >= this.maxFindings) return;
      }
    }
  }
}
