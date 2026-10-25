import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeFetch, collect } from './fake-fetch.js';
import { SnykConnector, toFinding as snykFinding } from '../src/connectors/snyk.js';
import { BlackDuckConnector, toFinding as bdFinding } from '../src/connectors/blackduck.js';
import { MendConnector, toFinding as mendFinding } from '../src/connectors/mend.js';
import { WizConnector, vulnerabilityToFinding, issueToFinding } from '../src/connectors/wiz.js';
import { AikidoConnector, toFinding as aikidoFinding } from '../src/connectors/aikido.js';
import { AppScanConnector, toFinding as appscanFinding } from '../src/connectors/appscan.js';
import { BurpConnector, toFinding as burpFinding } from '../src/connectors/burp.js';
import { AcunetixConnector, toFinding as acunetixFinding } from '../src/connectors/acunetix.js';

const snykCode = {
  id: 'issue-code-1',
  type: 'issue',
  attributes: {
    title: 'SQL Injection',
    type: 'code',
    effective_severity_level: 'high',
    status: 'open',
    ignored: false,
    classes: [{ id: 'CWE-89', source: 'CWE', type: 'weakness' }],
    coordinates: [{ representations: [{ sourceLocation: { file: 'src/db.js', region: { start: { line: 42, column: 3 } } } }] }],
    created_at: '2026-10-01T00:00:00Z',
  },
  relationships: { scan_item: { data: { id: 'proj-1', type: 'project' } } },
};

const snykDep = {
  id: 'issue-dep-1',
  attributes: {
    title: 'Prototype Pollution',
    type: 'package_vulnerability',
    effective_severity_level: 'high',
    status: 'open',
    problems: [{ id: 'SNYK-JS-LODASH-1040724', source: 'SNYK' }, { id: 'CVE-2021-23337', source: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' }],
    coordinates: [{ remedies: [{ description: 'Upgrade lodash to 4.17.21', details: { upgrade_package: '4.17.21' } }], representations: [{ dependency: { package_name: 'lodash', package_version: '4.17.20' } }] }],
  },
};

test('Snyk: code and dependency issues map to SAST and SCA', () => {
  const code = snykFinding(snykCode);
  assert.deepEqual([code.kind, code.severity, code.cwe, code.location.file, code.location.line], ['sast', 'high', 89, 'src/db.js', 42]);
  const dep = snykFinding(snykDep);
  assert.deepEqual([dep.kind, dep.cve, dep.pkg.name, dep.pkg.version, dep.pkg.fixedVersion], ['sca', 'CVE-2021-23337', 'lodash', '4.17.20', '4.17.21']);
  assert.match(dep.remediation, /Upgrade lodash/);
  assert.equal(snykFinding({ ...snykDep, attributes: { ...snykDep.attributes, ignored: true } }).status, 'accepted');
});

test('Snyk: finds the orgs, then follows links.next to the end', async () => {
  const { fetchImpl, calls } = fakeFetch([
    ['GET', '/rest/orgs', { data: [{ id: 'org-1' }] }],
    ['GET', '/rest/orgs/org-1/issues', (url) =>
      url.searchParams.get('starting_after')
        ? { data: [snykDep] }
        : { data: [snykCode], links: { next: '/orgs/org-1/issues?version=2024-10-15&limit=100&starting_after=abc' } }],
  ]);
  const findings = await collect(new SnykConnector({ token: 't' }, { fetchImpl }).findings());
  assert.equal(findings.length, 2);
  const issueCalls = calls.filter((c) => c.url.pathname.endsWith('/issues'));
  assert.equal(issueCalls[1].url.searchParams.get('starting_after'), 'abc');
  assert.equal(issueCalls[0].init.headers.Authorization, 'token t');
  assert.equal(new SnykConnector({ token: 't', region: 'eu' }).base, 'https://api.eu.snyk.io');
});

const bdRow = {
  componentName: 'lodash',
  componentVersionName: '4.17.20',
  componentVersion: 'https://bd/api/components/1/versions/2',
  vulnerabilityWithRemediation: { vulnerabilityName: 'CVE-2021-23337', severity: 'HIGH', baseScore: 7.2, cweId: 'CWE-94', remediationStatus: 'NEW', description: 'Command injection' },
};

test('Black Duck: a vulnerable BOM component maps to SCA, and signs in with its API token', async () => {
  const f = bdFinding(bdRow, { project: { name: 'shop' }, version: { versionName: '1.0', _meta: { href: 'https://bd/api/projects/1/versions/1' } } });
  assert.deepEqual([f.kind, f.severity, f.cve, f.cwe, f.pkg.name, f.asset.project], ['sca', 'high', 'CVE-2021-23337', 94, 'lodash', 'shop']);
  assert.equal(bdFinding({ ...bdRow, vulnerabilityWithRemediation: { ...bdRow.vulnerabilityWithRemediation, remediationStatus: 'PATCHED' } }).status, 'fixed');

  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/api/tokens/authenticate', { bearerToken: 'b', expiresInMilliseconds: 7_200_000 }],
    ['GET', '/api/projects', { items: [{ name: 'shop', _meta: { href: 'https://bd.example/api/projects/1' } }], totalCount: 1 }],
    ['GET', '/api/projects/1/versions', { items: [{ versionName: '1.0', _meta: { href: 'https://bd.example/api/projects/1/versions/1' } }], totalCount: 1 }],
    ['GET', '/api/projects/1/versions/1/vulnerable-bom-components', { items: [bdRow], totalCount: 1 }],
  ]);
  const findings = await collect(new BlackDuckConnector({ url: 'https://bd.example', token: 't' }, { fetchImpl }).findings());
  assert.equal(findings.length, 1);
  assert.equal(calls[0].init.headers.Authorization, 'token t');
  assert.equal(calls.at(-1).init.headers.Accept, 'application/vnd.blackducksoftware.bill-of-materials-6+json');
});

const mendRow = {
  uuid: 'f-1',
  name: 'CVE-2021-23337',
  component: { uuid: 'c-1', name: 'lodash-4.17.20.tgz', artifactId: 'lodash', version: '4.17.20', libraryType: 'javascript/Node.js', path: 'package.json' },
  vulnerability: { name: 'CVE-2021-23337', severity: 'HIGH', score: 7.2, description: 'Command injection' },
  topFix: { message: 'Upgrade to version', fixResolution: 'lodash - 4.17.21', url: 'https://github.com/lodash/lodash/commit/3469357' },
  findingInfo: { status: 'ACTIVE', detectedAt: '2026-09-01T00:00:00Z' },
};

test('Mend: login, then access token, then every project\'s security findings', async () => {
  const f = mendFinding(mendRow, { project: { name: 'shop' } });
  assert.deepEqual([f.kind, f.severity, f.cve, f.pkg.name, f.pkg.version], ['sca', 'high', 'CVE-2021-23337', 'lodash', '4.17.20']);
  assert.match(f.remediation, /4\.17\.21/);

  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/api/v3.0/login', { retVal: { refreshToken: 'r' } }],
    ['POST', '/api/v3.0/login/accessToken', { retVal: { jwtToken: 'j', jwtTTL: 1_800_000 } }],
    ['GET', '/api/v3.0/orgs/org-1/projects', { retVal: [{ uuid: 'p-1', name: 'shop' }] }],
    ['GET', '/api/v3.0/projects/p-1/dependencies/findings/security', { retVal: [mendRow] }],
  ]);
  const findings = await collect(new MendConnector({ email: 'a@b.c', userKey: 'k', orgUuid: 'org-1' }, { fetchImpl }).findings());
  assert.equal(findings.length, 1);
  assert.equal(calls[1].init.headers['wss-refresh-token'], 'r');
  assert.equal(calls[2].init.headers.Authorization, 'Bearer j');
});

test('Wiz: image vulnerabilities and cloud issues, through cursor pages', async () => {
  const vuln = {
    id: 'v-1', name: 'CVE-2023-44487', severity: 'HIGH', status: 'OPEN', detailedName: 'golang.org/x/net', version: '0.7.0', fixedVersion: '0.17.0',
    vulnerableAsset: { id: 'a-1', type: 'CONTAINER_IMAGE', name: 'shop/api:1.4', imageId: 'sha256:abc' },
  };
  const issue = {
    id: 'i-1', type: 'TOXIC_COMBINATION', severity: 'CRITICAL', status: 'OPEN',
    sourceRule: { __typename: 'Control', name: 'Publicly exposed VM with a critical vulnerability', resolutionRecommendation: 'Restrict ingress.' },
    entitySnapshot: { providerId: 'arn:aws:ec2:eu-west-1:123:instance/i-9', subscriptionExternalId: '123' },
  };
  const v = vulnerabilityToFinding(vuln);
  assert.deepEqual([v.kind, v.cve, v.asset.image, v.pkg.fixedVersion], ['container', 'CVE-2023-44487', 'shop/api:1.4', '0.17.0']);
  const i = issueToFinding(issue);
  assert.deepEqual([i.kind, i.severity, i.asset.resource, i.remediation], ['cloud', 'critical', 'arn:aws:ec2:eu-west-1:123:instance/i-9', 'Restrict ingress.']);

  let vulnPages = 0;
  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/oauth/token', { access_token: 'w', expires_in: 3600 }],
    ['POST', '/graphql', (url, init) => {
      const { query, variables } = JSON.parse(init.body);
      if (query.includes('vulnerabilityFindings')) {
        vulnPages += 1;
        return { data: { vulnerabilityFindings: { nodes: [vuln], pageInfo: variables.after ? { hasNextPage: false } : { hasNextPage: true, endCursor: 'c1' } } } };
      }
      return { data: { issuesV2: { nodes: [issue], pageInfo: { hasNextPage: false } } } };
    }],
  ]);
  const findings = await collect(new WizConnector({ clientId: 'id', clientSecret: 's', apiUrl: 'https://api.us17.app.wiz.io/graphql' }, { fetchImpl }).findings());
  assert.equal(findings.length, 3);
  assert.equal(vulnPages, 2);
  assert.match(calls[0].init.body.toString(), /audience=wiz-api/);
});

test('Aikido: every issue type maps to its kind', async () => {
  const issues = [
    { id: 1, type: 'open_source', severity: 'high', status: 'open', affected_package: 'lodash', installed_version: '4.17.20', patched_versions: ['4.17.21'], cve_id: 'CVE-2021-23337', code_repo_name: 'shop' },
    { id: 2, type: 'sast', severity: 'critical', status: 'open', rule: 'SQL injection', affected_file: 'src/db.js', start_line: 42, cwe_classes: ['CWE-89'], code_repo_name: 'shop' },
    { id: 3, type: 'leaked_secret', severity: 'critical', status: 'ignored', affected_file: '.env', start_line: 3 },
    { id: 4, type: 'surface_monitoring', severity: 'medium', status: 'open', rule: 'Missing security headers', affected_file: 'https://shop.example.com/login' },
  ];
  const kinds = issues.map((i) => aikidoFinding(i).kind);
  assert.deepEqual(kinds, ['sca', 'sast', 'secret', 'dast']);
  assert.equal(aikidoFinding(issues[2]).status, 'accepted');
  assert.equal(aikidoFinding(issues[3]).endpoint.url, 'https://shop.example.com/login');

  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/api/oauth/token', { access_token: 'k', expires_in: 3600 }],
    ['GET', '/api/public/v1/issues/export', issues],
  ]);
  const findings = await collect(new AikidoConnector({ clientId: 'id', clientSecret: 's' }, { fetchImpl }).findings());
  assert.equal(findings.length, 4);
  assert.equal(calls[0].init.headers.Authorization, `Basic ${Buffer.from('id:s').toString('base64')}`);
});

test('AppScan: SAST and DAST issues of every application, OData pages', async () => {
  const sast = { Id: 'a1', IssueType: 'SQL Injection', Severity: 'High', Status: 'Open', DiscoveryMethod: 'SAST', SourceFile: 'src/db.js', Line: 42, Cwe: 89 };
  const dast = { Id: 'a2', IssueType: 'Cross-Site Scripting', Severity: 'Medium', Status: 'Open', DiscoveryMethod: 'DAST', Location: 'https://shop.example.com/search', Element: 'q', Cwe: 79 };
  assert.deepEqual([appscanFinding(sast).kind, appscanFinding(sast).location.line], ['sast', 42]);
  assert.deepEqual([appscanFinding(dast).kind, appscanFinding(dast).endpoint.parameter], ['dast', 'q']);
  assert.equal(appscanFinding({ ...sast, Status: 'Noise' }).status, 'not-exploitable');

  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/api/v4/Account/ApiKeyLogin', { Token: 'x', Expire: new Date(Date.now() + 3_600_000).toISOString() }],
    ['GET', '/api/v4/Apps', { Items: [{ Id: 'app-1', Name: 'shop' }], Count: 1 }],
    ['GET', '/api/v4/Issues/Application/app-1', { Items: [sast, dast], Count: 2 }],
  ]);
  const findings = await collect(new AppScanConnector({ keyId: 'i', keySecret: 's' }, { fetchImpl }).findings());
  assert.equal(findings.length, 2);
  assert.equal(calls.at(-1).url.searchParams.get('$filter'), "Status ne 'Fixed'");
});

test('Burp Suite DAST: each site\'s latest scan, issues with their type\'s fix', async () => {
  const issue = {
    serial_number: '9001', severity: 'high', confidence: 'certain', origin: 'https://shop.example.com', path: '/search',
    issue_type: { name: 'Cross-site scripting (reflected)', description_html: '<p>Reflected <b>XSS</b></p>', remediation_html: '<p>Encode output.</p>', vulnerability_classifications_html: '<ul><li><a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79</a></li></ul>', references_html: '<a href="https://portswigger.net/web-security/cross-site-scripting">XSS</a>' },
  };
  const f = burpFinding(issue, { scan: { id: 's1', site_id: 'site-1', site_name: 'shop' } });
  assert.deepEqual([f.kind, f.severity, f.cwe, f.endpoint.url, f.remediation], ['dast', 'high', 79, 'https://shop.example.com/search', 'Encode output.']);

  const { fetchImpl } = fakeFetch([
    ['POST', '/graphql/v1', (url, init) => {
      const { query } = JSON.parse(init.body);
      if (query.includes('scans(')) return { data: { scans: [{ id: 's2', site_id: 'site-1', site_name: 'shop' }, { id: 's1', site_id: 'site-1', site_name: 'shop' }] } };
      return { data: { scan: { issues: [issue] } } };
    }],
  ]);
  const findings = await collect(new BurpConnector({ url: 'https://burp.example', apiKey: 'k' }, { fetchImpl }).findings());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].raw.scanId, 's2');
});

test('Acunetix: numeric severities, CWE from tags, cursor pages', async () => {
  const vuln = { vuln_id: 'v1', vt_name: 'SQL injection', severity: 4, status: 'open', affects_url: 'https://shop.example.com/item', affects_detail: 'id', tags: ['CWE-89', 'sql_injection'] };
  const f = acunetixFinding(vuln);
  assert.deepEqual([f.kind, f.severity, f.cwe, f.endpoint.parameter], ['dast', 'critical', 89, 'id']);

  const { fetchImpl, calls } = fakeFetch([
    ['GET', '/api/v1/vulnerabilities', (url) => (url.searchParams.get('c') ? { vulnerabilities: [vuln], pagination: {} } : { vulnerabilities: [vuln], pagination: { next_cursor: 'n1' } })],
  ]);
  const findings = await collect(new AcunetixConnector({ url: 'https://acx.example:3443', apiKey: 'k' }, { fetchImpl }).findings());
  assert.equal(findings.length, 2);
  assert.equal(calls[0].init.headers['X-Auth'], 'k');
  assert.equal(calls[0].url.searchParams.get('q'), 'status:open');
});
