import fs from 'node:fs';
import { ENGINES } from './engines.js';

/** "${NAME}" in any string, recursively, filled from env; a name env does not have becomes ''. */
export function interpolate(value, env = process.env) {
  if (typeof value === 'string') return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_, name) => env[name] ?? '');
  if (Array.isArray(value)) return value.map((item) => interpolate(item, env));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, interpolate(v, env)]));
  return value;
}

/**
 * The engines to connect, from a parsed config.
 * @returns {{id: string, config: object}[]}
 */
export function enginesFrom(config, env = process.env) {
  const blocks = config?.engines ?? {};
  const unknown = Object.keys(blocks).filter((id) => !ENGINES[id]);
  if (unknown.length) {
    throw new Error(`remify does not know ${unknown.join(', ')}. It connects to: ${Object.keys(ENGINES).join(', ')}.`);
  }
  return Object.entries(blocks)
    .filter(([, block]) => block && block.enabled !== false)
    .map(([id, block]) => ({ id, config: interpolate(block, env) }));
}

export function loadConfig(file = 'remify.config.json', env = process.env) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`No ${file}. Copy remify.config.example.json to ${file} and keep the engines you use.`);
    throw new Error(`${file} is not valid JSON: ${error.message}`);
  }
  return enginesFrom(parsed, env);
}
