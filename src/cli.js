#!/usr/bin/env node
/**
 * remify connect                 check every engine in remify.config.json, all at once
 * remify fetch [--out file]      read every finding from every engine, merge duplicates, print a summary
 *
 * Options: --config <file>, --engines a,b (only these), --max <n> (findings per engine), --out <file> (JSON).
 */

import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { loadConfig } from './config.js';
import { connectorsFor, connectAll, fetchAll } from './run.js';
import { mergeFindings, summarize } from './merge.js';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string', default: 'remify.config.json' },
    engines: { type: 'string' },
    max: { type: 'string' },
    out: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});

const usage = `Usage: remify <connect|fetch> [--config remify.config.json] [--engines checkmarx,snyk] [--max 1000] [--out findings.json]`;

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
  const connectors = connectorsFor(engines, { maxFindings: values.max ? Number(values.max) : Infinity });

  if (command === 'connect') {
    const results = await connectAll(connectors);
    for (const r of results) console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.label.padEnd(16)} ${r.detail}`);
    return results.every((r) => r.ok) ? 0 : 1;
  }

  const { findings, engines: perEngine } = await fetchAll(connectors);
  for (const e of perEngine) console.log(`${e.ok ? 'ok  ' : 'FAIL'}  ${e.label.padEnd(16)} ${e.count} findings${e.error ? `, stopped: ${e.error}` : ''}`);
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
