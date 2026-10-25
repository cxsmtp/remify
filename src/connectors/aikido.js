/**
 * Aikido: every issue type it finds (open source, SAST, secrets, IaC,
 * containers, cloud, surface monitoring/DAST), from one export.
 *
 *   POST /api/oauth/token                    Basic clientId:clientSecret, client credentials
 *   GET  /api/public/v1/issues/export        every issue, one array
 */

import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';

const KIND_BY_TYPE = {
  open_source: 'sca',
  license: 'sca',
  eol: 'sca',
  malware: 'sca',
  sast: 'sast',
  mobile: 'sast',
  leaked_secret: 'secret',
  iac: 'iac',
  docker_container: 'container',
  cloud: 'cloud',
  surface_monitoring: 'dast',
  scm_security: 'other',
};

const STATUS = { closed: 'fixed', ignored: 'accepted', snoozed: 'accepted' };

const isoFromUnix = (value) => (Number.isFinite(Number(value)) && Number(value) > 0 ? new Date(Number(value) * 1000).toISOString() : value ?? null);

export function toFinding(issue) {
  const kind = KIND_BY_TYPE[issue.type] ?? 'other';
  const patched = [].concat(issue.patched_versions ?? []).filter(Boolean);
  return makeFinding({
    engine: 'aikido',
    nativeId: issue.id,
    kind,
    title: issue.rule ?? issue.cve_id ?? issue.type,
    severity: issue.severity,
    status: STATUS[issue.status] ?? 'open',
    cwe: [].concat(issue.cwe_classes ?? [])[0],
    cve: issue.cve_id,
    asset: {
      repo: issue.code_repo_name,
      image: issue.container_repo_name,
      resource: issue.cloud_name,
      url: kind === 'dast' ? issue.affected_file : null,
    },
    location: { file: kind === 'dast' ? null : issue.affected_file, line: issue.start_line },
    pkg: { name: issue.affected_package, version: issue.installed_version, fixedVersion: patched[0], ecosystem: issue.programming_language },
    endpoint: kind === 'dast' ? { url: issue.affected_file } : {},
    remediation: patched.length ? `Upgrade ${issue.affected_package} to ${patched[0]}.` : null,
    firstFoundAt: isoFromUnix(issue.first_detected_at),
    raw: issue,
  });
}

export class AikidoConnector extends Connector {
  static id = 'aikido';
  static label = 'Aikido';
  static required = ['clientId', 'clientSecret'];

  #token = null;
  #expiresAt = 0;

  get base() {
    return String(this.config.url || 'https://app.aikido.dev').replace(/\/+$/, '');
  }

  async authHeaders() {
    if (!this.#token || Date.now() >= this.#expiresAt) {
      const basic = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64');
      const answer = await request(this.label, `${this.base}/api/oauth/token`, {
        method: 'POST',
        headers: { Authorization: `Basic ${basic}` },
        body: { grant_type: 'client_credentials' },
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.access_token) throw new Error('Aikido gave no access token for this client.');
      this.#token = answer.access_token;
      this.#expiresAt = Date.now() + Number(answer.expires_in ?? 3600) * 1000 - 60_000;
    }
    return { Authorization: `Bearer ${this.#token}` };
  }

  async check() {
    await this.authHeaders();
    return 'token issued';
  }

  async *findings() {
    const issues = await this.call(`${this.base}/api/public/v1/issues/export`, { query: this.config.includeClosed ? {} : { filter_status: 'open' } });
    let count = 0;
    for (const issue of Array.isArray(issues) ? issues : issues?.issues ?? []) {
      yield toFinding(issue);
      if (++count >= this.maxFindings) return;
    }
  }
}
