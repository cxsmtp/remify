import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFinding } from '../src/finding.js';
import { mergeFindings, matchKey, normalizePath, summarize } from '../src/merge.js';
import { toFinding as cx } from '../src/connectors/checkmarx.js';
import { missingAuth, ssrf } from './fixtures/checkmarx.js';

const f = (over) => makeFinding({ engine: 'x', nativeId: Math.random(), kind: 'sast', title: 't', ...over });

test('paths agree whatever the engine writes', () => {
  assert.equal(normalizePath('/src/DB.js'), 'src/db.js');
  assert.equal(normalizePath('.\\src\\db.js'), 'src/db.js');
});

test('ten reports of one line become one issue, and the one triaged not exploitable is left out', () => {
  const findings = missingAuth.map((row) => cx(row, { project: { id: 'p1', repoUrl: 'https://github.com/cxsmtp/CxDetectionDateBaseReminder' } }));
  const issues = mergeFindings(findings);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].reports, 9);
  assert.equal(issues[0].severity, 'critical');
  assert.equal(issues[0].corroborated, false);
});

test('the same SQL injection from Checkmarx, Snyk and AppScan is one corroborated issue', () => {
  const issues = mergeFindings([
    f({ engine: 'checkmarx', kind: 'sast', title: 'SQL_Injection', severity: 'high', cwe: 89, location: { file: '/src/db.js', line: 42 }, asset: { repo: 'https://github.com/acme/shop' } }),
    f({ engine: 'snyk', kind: 'sast', title: 'SQL Injection', severity: 'critical', cwe: 'CWE-89', location: { file: 'src/db.js', line: 42 } }),
    f({ engine: 'appscan', kind: 'sast', title: 'SQL Injection', severity: 'high', cwe: 89, location: { file: 'src\\db.js', line: 42 }, asset: { repo: 'acme/shop.git' } }),
  ]);
  assert.equal(issues.length, 1);
  assert.deepEqual(issues[0].engines, ['appscan', 'checkmarx', 'snyk']);
  assert.equal(issues[0].severity, 'critical');
  assert.equal(issues[0].corroborated, true);
});

test('one CVE in one package version, from four SCA engines, is one issue', () => {
  const pkg = { name: 'lodash', version: '4.17.20' };
  const issues = mergeFindings(['checkmarx', 'snyk', 'blackduck', 'mend'].map((engine) => f({ engine, kind: 'sca', cve: 'CVE-2021-23337', pkg: { ...pkg, name: engine === 'mend' ? 'Lodash' : 'lodash' } })));
  assert.equal(issues.length, 1);
  assert.equal(issues[0].engines.length, 4);
});

test('the same file and line in two different repositories stays two issues', () => {
  const issues = mergeFindings([
    f({ engine: 'checkmarx', cwe: 89, location: { file: 'src/db.js', line: 42 }, asset: { repo: 'acme/shop' } }),
    f({ engine: 'snyk', cwe: 89, location: { file: 'src/db.js', line: 42 }, asset: { repo: 'acme/billing' } }),
  ]);
  assert.equal(issues.length, 2);
});

test('different weaknesses at one line, or one weakness at two lines, are not merged', () => {
  const a = f({ cwe: 89, location: { file: 'a.js', line: 1 } });
  assert.notEqual(matchKey(a), matchKey(f({ cwe: 79, location: { file: 'a.js', line: 1 } })));
  assert.notEqual(matchKey(a), matchKey(f({ cwe: 89, location: { file: 'a.js', line: 2 } })));
});

test('DAST matches on host, path, parameter and CWE, not the query string', () => {
  const issues = mergeFindings([
    f({ engine: 'burp', kind: 'dast', cwe: 79, endpoint: { url: 'https://shop.example.com/search?q=1', parameter: 'q' } }),
    f({ engine: 'acunetix', kind: 'dast', cwe: 79, endpoint: { url: 'https://SHOP.example.com/search/', parameter: 'q' } }),
  ]);
  assert.equal(issues.length, 1);
});

test('a finding with nothing to match on stands alone', () => {
  const issues = mergeFindings([f({ kind: 'other' }), f({ kind: 'other' })]);
  assert.equal(issues.length, 2);
});

test('summary counts findings, open reports, issues and corroboration', () => {
  const findings = [cx(ssrf, { project: { id: 'p' } }), ...missingAuth.map((r) => cx(r, { project: { id: 'p' } }))];
  const s = summarize(findings, mergeFindings(findings));
  assert.deepEqual(s, { findings: 11, open: 10, issues: 2, corroborated: 0, bySeverity: { critical: 1, high: 1 } });
});
