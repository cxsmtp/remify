import test from 'node:test';
import assert from 'node:assert/strict';
import { enginesFrom, interpolate } from '../src/config.js';
import { connectorsFor, connectAll, fetchAll } from '../src/run.js';
import { normalizeSeverity, parseCve, parseCwe, severityFromScore } from '../src/finding.js';
import { fakeFetch } from './fake-fetch.js';

test('severity words and scores from any engine', () => {
  assert.deepEqual(['Critical', 'HIGH', 'moderate', 'Low', 'Informational', 'weird'].map(normalizeSeverity), ['critical', 'high', 'medium', 'low', 'info', 'info']);
  assert.deepEqual([9.8, 7.5, 5, 2, 0].map(severityFromScore), ['critical', 'high', 'medium', 'low', 'info']);
  assert.equal(parseCwe('CWE-918'), 918);
  assert.equal(parseCve('see cve-2021-44228 now'), 'CVE-2021-44228');
});

test('config: secrets come from the environment, unknown engines are named, disabled ones skipped', () => {
  assert.deepEqual(interpolate({ a: '${X}', b: ['${Y}-z'] }, { X: '1', Y: '2' }), { a: '1', b: ['2-z'] });
  const engines = enginesFrom({ engines: { snyk: { token: '${SNYK_TOKEN}' }, wiz: { enabled: false } } }, { SNYK_TOKEN: 'abc' });
  assert.deepEqual(engines, [{ id: 'snyk', config: { token: 'abc' } }]);
  assert.throws(() => enginesFrom({ engines: { qualys: {} } }), /does not know qualys/);
});

test('connect: every engine at once; a missing setting or a refusal never stops the others', async () => {
  const { fetchImpl } = fakeFetch([
    ['GET', '/rest/self', { data: { attributes: { name: 'Kyle' } } }],
    ['GET', '/rest/orgs', { data: [{ id: 'o1' }] }],
    ['GET', '/api/v1/me', { status: 401, statusText: 'Unauthorized', body: {} }],
  ]);
  const connectors = connectorsFor(
    enginesFrom({ engines: { snyk: { token: 't' }, acunetix: { url: 'https://acx.example', apiKey: 'bad' }, wiz: { clientId: 'x' } } }),
    { fetchImpl },
  );
  const results = await connectAll(connectors);
  assert.deepEqual(results.map((r) => [r.id, r.ok]), [['snyk', true], ['acunetix', false], ['wiz', false]]);
  assert.match(results[0].detail, /Kyle, 1 org/);
  assert.match(results[1].detail, /401.*credentials/);
  assert.match(results[2].detail, /missing clientSecret, apiUrl/);
});

test('fetch: findings of the engines that answered, and why the others did not', async () => {
  const { fetchImpl } = fakeFetch([
    ['GET', '/api/v1/vulnerabilities', { vulnerabilities: [{ vuln_id: 'v', vt_name: 'XSS', severity: 2, affects_url: 'https://a.example/x' }], pagination: {} }],
  ]);
  const connectors = connectorsFor(enginesFrom({ engines: { acunetix: { url: 'https://acx.example', apiKey: 'k' }, snyk: { token: 't', orgId: 'o1' } } }), { fetchImpl });
  const { findings, engines } = await fetchAll(connectors);
  assert.equal(findings.length, 1);
  assert.equal(engines[0].ok, true);
  assert.equal(engines[1].ok, false);
  assert.match(engines[1].error, /404/);
});
