#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { loadConfig } from './config.js';
import { connectorsFor, connectAll, fetchAll } from './run.js';
import { mergeFindings, summarize } from './merge.js';
import { Checkpoint } from './checkpoint.js';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string', default: 'remify.config.json' },
    engines: { type: 'string' },
    max: { type: 'string' },
    out: { type: 'string' },
    concurrency: { type: 'string' },
    resume: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});

const usage = `Usage: remify <connect|fetch> [--config remify.config.json] [--engines checkmarx,snyk] [--max 1000] [--concurrency 8] [--out findings.json] [--resume .remify/runs/<time>]`;

async function main() {
  const command = positionals[0];
  if (values.help || !['connect', 'fetch'].includes(command)) {
    console.log(usage);
    return command && !values.help ? 1 : 0;
  }

  let engines = loadConfig(values.config);
  if (values.engines) {
    const only = new Set(values.engines.split(',').map((s) => s.trim()));
    engines = engines.filter((e) => only.has(e.id));
  }
  if (!engines.length) {
    console.log('No engines to connect: add at least one to the config.');
    return 1;
  }
  const connectors = connectorsFor(engines, {
    maxFindings: values.max ? Number(values.max) : Infinity,
    concurrency: values.concurrency ? Number(values.concurrency) : undefined,
  });

  if (command === 'connect') {
    const results = await connectAll(connectors);
    for (const r of results) console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.label.padEnd(16)} ${r.detail}`);
    return results.every((r) => r.ok) ? 0 : 1;
  }

  const runDir = values.resume || path.join('.remify', 'runs', new Date().toISOString().replace(/[:.]/g, '-'));
  const checkpoint = new Checkpoint(runDir);
  const started = Date.now();
  let done = 0;
  const onUnit = process.stderr.isTTY ? () => process.stderr.write(`\r${++done} units read`) : undefined;
  const { findings, engines: perEngine } = await fetchAll(connectors, { checkpoint, onUnit });
  if (onUnit) process.stderr.write('\n');
  for (const e of perEngine) {
    const units = e.units ? ` from ${e.units} units${e.resumed ? ` (${e.resumed} resumed)` : ''}` : '';
    console.log(`${e.ok ? 'ok  ' : 'FAIL'}  ${e.label.padEnd(16)} ${e.count} findings${units}${e.error ? `, ${e.error}` : ''}`);
  }
  console.log(`Read in ${((Date.now() - started) / 1000).toFixed(1)} s. Run saved in ${runDir}${perEngine.every((e) => e.ok) ? '' : `; to retry only what failed: remify fetch --resume ${runDir}`}`);
  const issues = mergeFindings(findings);
  const s = summarize(findings, issues);
  const severities = Object.entries(s.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ');
  console.log(`\n${s.findings} findings, ${s.open} open → ${s.issues} issues after merging (${s.corroborated} reported by more than one engine). ${severities}`);
  if (values.out) {
    fs.writeFileSync(values.out, JSON.stringify({ fetchedAt: new Date().toISOString(), engines: perEngine, summary: s, issues }, null, 2));
    console.log(`Written to ${values.out}`);
  }
  return perEngine.every((e) => e.ok) ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(error.message);
    process.exit(1);
  },
);
