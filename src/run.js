/**
 * Every configured engine at once: connect them all in one go, and fetch all
 * their findings. One engine failing never stops the others; it is reported
 * with its reason beside their results.
 */

import { ENGINES } from './engines.js';

/** Connectors for the configured engines. */
export function connectorsFor(engines, options = {}) {
  return engines.map(({ id, config }) => new ENGINES[id](config, options));
}

/**
 * Check every connection in parallel.
 * @returns {Promise<{id: string, label: string, ok: boolean, detail: string}[]>}
 */
export async function connectAll(connectors) {
  return Promise.all(
    connectors.map(async (connector) => {
      const base = { id: connector.id, label: connector.label };
      const missing = connector.missingSettings();
      if (missing.length) return { ...base, ok: false, detail: `missing ${missing.join(', ')}` };
      try {
        return { ...base, ok: true, detail: await connector.check() };
      } catch (error) {
        return { ...base, ok: false, detail: error.message };
      }
    }),
  );
}

/**
 * Every finding from every engine, read in parallel.
 * @returns {Promise<{findings: object[], engines: {id: string, label: string, ok: boolean, count: number, error?: string}[]}>}
 */
export async function fetchAll(connectors, { onFinding } = {}) {
  const findings = [];
  const engines = await Promise.all(
    connectors.map(async (connector) => {
      const base = { id: connector.id, label: connector.label };
      const missing = connector.missingSettings();
      if (missing.length) return { ...base, ok: false, count: 0, error: `missing ${missing.join(', ')}` };
      let count = 0;
      try {
        for await (const finding of connector.findings()) {
          findings.push(finding);
          count += 1;
          onFinding?.(finding);
        }
        return { ...base, ok: true, count };
      } catch (error) {
        // What was read before the failure is kept.
        return { ...base, ok: false, count, error: error.message };
      }
    }),
  );
  return { findings, engines };
}
