import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mapPool, numberedPages, countedPages } from '../src/pool.js';
import { Checkpoint } from '../src/checkpoint.js';
import { CheckmarxConnector } from '../src/connectors/checkmarx.js';
import { connectorsFor, fetchAll } from '../src/run.js';
import { fakeFetch, collect } from './fake-fetch.js';
import { ssrf, fakeApiKey } from './fixtures/checkmarx.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'remify-'));

test('mapPool keeps to its ceiling and answers in order', async () => {
  let inFlight = 0;
  let peak = 0;
  const out = await mapPool([...Array(20).keys()], 5, async (n) => {
    peak = Math.max(peak, ++inFlight);
    await sleep(5);
    inFlight -= 1;
    return n * 2;
  });
  assert.equal(peak, 5);
  assert.deepEqual(out, [...Array(20).keys()].map((n) => n * 2));
});

test('numbered pages: the first alone, then read ahead, stop at the first short page, drop the rest', async () => {
  const asked = [];
  const rows = await collect(numberedPages(async (page) => {
    asked.push(page);
    return page < 5 ? [page, page] : page === 5 ? [5] : [];
  }, { pageSize: 2, ahead: 4 }));
  assert.deepEqual(rows, [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5]);
  assert.deepEqual(asked, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
});

test('counted pages: after the first page, the others are read at once', async () => {
  let inFlight = 0;
  let peak = 0;
  const rows = await collect(countedPages(async (offset) => {
    peak = Math.max(peak, ++inFlight);
    await sleep(5);
    inFlight -= 1;
    return { rows: [offset], total: 10 };
  }, { pageSize: 1, limit: 4 }));
  assert.deepEqual(rows, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(peak, 4);
});

/** A Checkmarx tenant with `projects` projects, one scan each, one result per scan; `fail` names project ids whose results fail. */
function tenant({ projects, latencyMs = 0, fail = new Set() }) {
  const stats = { tokenCalls: 0, resultCalls: new Map(), inFlight: 0, peak: 0 };
  const slow = (answer) => async (url, init) => {
    stats.inFlight += 1;
    stats.peak = Math.max(stats.peak, stats.inFlight);
    try {
      if (latencyMs) await sleep(latencyMs);
      return typeof answer === 'function' ? answer(url, init) : answer;
    } finally {
      stats.inFlight -= 1;
    }
  };
  const all = Array.from({ length: projects }, (_, i) => ({ id: `p${i}`, name: `project-${i}` }));
  const { fetchImpl, calls } = fakeFetch([
    ['POST', /token$/, () => {
      stats.tokenCalls += 1;
      return { access_token: 'tok', expires_in: 3600 };
    }],
    ['GET', '/api/projects', slow((url) => {
      const offset = Number(url.searchParams.get('offset'));
      const limit = Number(url.searchParams.get('limit'));
      return { projects: all.slice(offset, offset + limit), totalCount: all.length };
    })],
    ['GET', '/api/projects/last-scan', slow((url) => Object.fromEntries(url.searchParams.getAll('project-ids').map((id) => [id, { id: `s-${id}`, branch: 'main' }])))],
    ['GET', '/api/results/', slow((url) => {
      const scanId = url.searchParams.get('scan-id');
      const projectId = scanId.slice(2);
      if (url.searchParams.get('offset') === '0') stats.resultCalls.set(projectId, (stats.resultCalls.get(projectId) ?? 0) + 1);
      if (fail.has(projectId)) return { status: 500, statusText: 'Internal Server Error', body: {} };
      return { results: url.searchParams.get('offset') === '0' ? [{ ...ssrf, id: `r-${projectId}` }] : [] };
    })],
  ]);
  return { fetchImpl, calls, stats };
}

test('a tenant of 1,900 projects with 20 ms answers is read in seconds, signing in once', async () => {
  const { fetchImpl, stats } = tenant({ projects: 1900, latencyMs: 20 });
  const connector = new CheckmarxConnector({ apiKey: fakeApiKey(), concurrency: 16 }, { fetchImpl });
  const started = Date.now();
  const { findings, units } = await connector.readAll();
  const seconds = (Date.now() - started) / 1000;
  assert.equal(findings.length, 1900);
  assert.equal(units.length, 1900);
  assert.equal(stats.tokenCalls, 1);
  // 16 projects at once, held to 24 requests in flight.
  assert.ok(stats.peak >= 16 && stats.peak <= 24, `peak ${stats.peak}`);
  // One at a time this is about 1,900 × 20 ms ≈ 40 s; at once it is a few seconds.
  assert.ok(seconds < 15, `took ${seconds}s`);
  console.log(`# 1,900 projects read in ${seconds.toFixed(1)} s, ${stats.peak} requests at once at most`);
});

test('a project that fails never stops the others, and is named', async () => {
  const { fetchImpl } = tenant({ projects: 20, fail: new Set(['p3', 'p7']) });
  const [connector] = connectorsFor([{ id: 'checkmarx', config: { apiKey: fakeApiKey() } }], { fetchImpl });
  const { findings, engines } = await fetchAll([connector]);
  assert.equal(findings.length, 18);
  assert.equal(engines[0].ok, false);
  assert.deepEqual(engines[0].failed.map((f) => f.key).sort(), ['p3:s-p3', 'p7:s-p7']);
  assert.match(engines[0].error, /2 of 20 units failed.*500/);
});

test('a stopped run carries on: only the units that failed are read again', async () => {
  const dir = tempDir();
  try {
    const first = tenant({ projects: 20, fail: new Set(['p3', 'p7']) });
    await fetchAll(connectorsFor([{ id: 'checkmarx', config: { apiKey: fakeApiKey() } }], { fetchImpl: first.fetchImpl }), { checkpoint: new Checkpoint(dir) });
    assert.equal(new Checkpoint(dir).count('checkmarx'), 18);

    const second = tenant({ projects: 20 });
    const { findings, engines } = await fetchAll(connectorsFor([{ id: 'checkmarx', config: { apiKey: fakeApiKey() } }], { fetchImpl: second.fetchImpl }), { checkpoint: new Checkpoint(dir) });
    assert.equal(findings.length, 20);
    assert.equal(engines[0].ok, true);
    assert.equal(engines[0].resumed, 18);
    assert.deepEqual([...second.stats.resultCalls.keys()].sort(), ['p3', 'p7']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a new scan of a project is a new unit, so a resumed run never serves stale results', async () => {
  const dir = tempDir();
  try {
    const checkpoint = new Checkpoint(dir);
    checkpoint.save('checkmarx', 'p0:s-old', [{ id: 'stale' }]);
    const { fetchImpl, stats } = tenant({ projects: 1 });
    const { findings } = await new CheckmarxConnector({ apiKey: fakeApiKey() }, { fetchImpl }).readAll({ checkpoint });
    assert.equal(findings[0].nativeId, 'p0:r-p0');
    assert.equal(stats.resultCalls.get('p0'), 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a unit cut short by --max is not saved as finished', async () => {
  const dir = tempDir();
  try {
    const checkpoint = new Checkpoint(dir);
    const { fetchImpl } = fakeFetch([
      ['POST', /token$/, { access_token: 'tok' }],
      ['GET', '/api/projects', { projects: [{ id: 'p1', name: 'one' }], totalCount: 1 }],
      ['GET', '/api/projects/last-scan', { p1: { id: 's1' } }],
      ['GET', '/api/results/', (url) => ({ results: url.searchParams.get('offset') === '0' ? [ssrf, ssrf, ssrf] : [] })],
    ]);
    const { findings } = await new CheckmarxConnector({ apiKey: fakeApiKey() }, { fetchImpl, maxFindings: 2 }).readAll({ checkpoint });
    assert.equal(findings.length, 2);
    assert.equal(checkpoint.count('checkmarx'), 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a checkpoint file left half-written is ignored, not trusted', () => {
  const dir = tempDir();
  try {
    const checkpoint = new Checkpoint(dir);
    checkpoint.save('snyk', 'org-1', [{ id: 'a' }]);
    const [file] = fs.readdirSync(path.join(dir, 'snyk'));
    fs.writeFileSync(path.join(dir, 'snyk', file), '{"key":"org-1","findings":[{"id"');
    assert.equal(checkpoint.load('snyk', 'org-1'), null);
    assert.deepEqual(checkpoint.load('snyk', 'org-2'), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
