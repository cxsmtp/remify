import test from 'node:test';
import assert from 'node:assert/strict';
import { CheckmarxConnector, deriveConnection, parsePackageIdentifier, toFinding } from '../src/connectors/checkmarx.js';
import { fakeFetch, collect } from './fake-fetch.js';
import { ssrf, secret, missingAuth, lodash, fakeApiKey } from './fixtures/checkmarx.js';

test('the API key alone gives the tenant, IAM, API and token URLs', () => {
  const c = deriveConnection(fakeApiKey());
  assert.equal(c.tenant, 'acme');
  assert.equal(c.iamUrl, 'https://eu.iam.checkmarx.net');
  assert.equal(c.apiUrl, 'https://eu.ast.checkmarx.net');
  assert.equal(c.tokenUrl, 'https://eu.iam.checkmarx.net/auth/realms/acme/protocol/openid-connect/token');
  assert.equal(deriveConnection(fakeApiKey('https://iam.checkmarx.net/auth/realms/x')).apiUrl, 'https://ast.checkmarx.net');
  assert.throws(() => deriveConnection('not-a-jwt'), /does not name its tenant/);
});

test('a SAST row keeps its CWE and the whole data flow, source first', () => {
  const f = toFinding(ssrf, { project: { id: 'p1', name: 'CxDetectionDateBaseReminder', repoUrl: 'https://github.com/cxsmtp/CxDetectionDateBaseReminder' }, scan: { id: 's1', branch: 'main' } });
  assert.equal(f.id, 'checkmarx:p1:I1ZRUsG8QTqktyAPlZSWsQQn+sc=');
  assert.equal(f.kind, 'sast');
  assert.equal(f.severity, 'high');
  assert.equal(f.cwe, 918);
  assert.equal(f.location.file, '/src/cxone/endpoints.js');
  assert.equal(f.location.line, 180);
  assert.equal(f.location.dataFlow.length, 3);
  assert.equal(f.location.dataFlow.at(-1).file, '/src/cxone/auth.js');
  assert.equal(f.asset.branch, 'main');
  assert.equal(f.raw.scanId, 's1');
});

test('a secret keeps Checkmarx One\'s own fix advice, still redacted', () => {
  const f = toFinding(secret, { project: { id: 'p1' } });
  assert.equal(f.kind, 'secret');
  assert.equal(f.severity, 'critical');
  assert.equal(f.location.file, '/test/connection-guard.e2e.test.js');
  assert.equal(f.location.line, 157);
  assert.match(f.remediation, /secret manager/);
  assert.match(f.remediation, /rotate/);
  assert.doesNotMatch(JSON.stringify(f), /0f8f[0-9a-f]{4}/);
});

test('an SCA row names the package, version and fix', () => {
  assert.deepEqual(parsePackageIdentifier('Npm-@scope/some-lib-1.2.3'), { ecosystem: 'npm', name: '@scope/some-lib', version: '1.2.3' });
  const f = toFinding(lodash, { project: { id: 'p1' } });
  assert.equal(f.kind, 'sca');
  assert.equal(f.cve, 'CVE-2021-23337');
  assert.deepEqual([f.pkg.name, f.pkg.version, f.pkg.fixedVersion], ['lodash', '4.17.20', '4.17.21']);
  assert.equal(f.remediation, 'Upgrade lodash to 4.17.21.');
});

test('a result triaged not exploitable is not open', () => {
  assert.equal(toFinding(missingAuth[4], {}).status, 'not-exploitable');
  assert.equal(toFinding(missingAuth[0], {}).status, 'open');
});

test('findings() signs in once and reads every project\'s latest scan, every page', async () => {
  const resultsPage = (url) => {
    const page = Number(url.searchParams.get('offset'));
    const all = [ssrf, secret, lodash, ...missingAuth];
    const size = Number(url.searchParams.get('limit'));
    // 200 per page: make page 0 full by padding, page 1 short.
    if (page === 0) return { results: Array.from({ length: size }, (_, i) => all[i % all.length]), totalCount: size + 3 };
    return { results: all.slice(0, 3), totalCount: size + 3 };
  };
  const { fetchImpl, calls } = fakeFetch([
    ['POST', '/auth/realms/acme/protocol/openid-connect/token', { access_token: 'tok', expires_in: 300 }],
    ['GET', '/api/projects', { projects: [{ id: 'p1', name: 'one' }, { id: 'p2', name: 'two' }], totalCount: 2 }],
    ['GET', '/api/projects/last-scan', { p1: { id: 's1', branch: 'main' } }],
    ['GET', '/api/results/', resultsPage],
  ]);
  const connector = new CheckmarxConnector({ apiKey: fakeApiKey() }, { fetchImpl });
  const findings = await collect(connector.findings());
  assert.equal(findings.length, 203);
  assert.equal(calls.filter((c) => c.method === 'POST').length, 1);
  const results = calls.filter((c) => c.url.pathname === '/api/results/');
  assert.deepEqual(results.map((c) => c.url.searchParams.get('offset')), ['0', '1']);
  assert.equal(results[0].init.headers.Authorization, 'Bearer tok');
  assert.equal(results[0].init.headers.Accept, 'application/json; version=1.0');
});

test('maxFindings stops reading early', async () => {
  const { fetchImpl } = fakeFetch([
    ['POST', /token$/, { access_token: 'tok' }],
    ['GET', '/api/projects', { projects: [{ id: 'p1', name: 'one' }] }],
    ['GET', '/api/projects/last-scan', { p1: { id: 's1' } }],
    ['GET', '/api/results/', { results: missingAuth }],
  ]);
  const findings = await collect(new CheckmarxConnector({ apiKey: fakeApiKey() }, { fetchImpl, maxFindings: 3 }).findings());
  assert.equal(findings.length, 3);
});
