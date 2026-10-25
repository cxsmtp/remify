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
 *
 * @param {{checkpoint?: import('./checkpoint.js').Checkpoint, onUnit?: (engine: string, unit: object) => void}} [options]
 * @returns {Promise<{findings: object[], engines: {id: string, label: string, ok: boolean, count: number, units: number, resumed: number, failed: {key: string, error: string}[], error?: string}[]}>}
 */
export async function fetchAll(connectors, { checkpoint, onUnit } = {}) {
  const findings = [];
  const engines = await Promise.all(
    connectors.map(async (connector) => {
      const base = { id: connector.id, label: connector.label, count: 0, units: 0, resumed: 0, failed: [] };
      const missing = connector.missingSettings();
      if (missing.length) return { ...base, ok: false, error: `missing ${missing.join(', ')}` };
      try {
        const result = await connector.readAll({ checkpoint, onUnit: onUnit && ((unit) => onUnit(connector.id, unit)) });
        findings.push(...result.findings);
        const failed = result.units.filter((u) => !u.ok).map((u) => ({ key: u.key, error: u.error }));
        return {
          ...base,
          ok: failed.length === 0,
          count: result.findings.length,
          units: result.units.length,
          resumed: result.units.filter((u) => u.resumed).length,
          failed,
          ...(failed.length ? { error: `${failed.length} of ${result.units.length} units failed, first: ${failed[0].error}` } : {}),
        };
      } catch (error) {
        // Listing the units failed: nothing of this engine could be read.
        return { ...base, ok: false, error: error.message };
      }
    }),
  );
  return { findings, engines };
}
