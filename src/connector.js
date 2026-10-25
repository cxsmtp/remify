import { request } from './http.js';
import { mapPool } from './pool.js';

/** Units read at once per engine, unless its config says otherwise (`concurrency`). */
export const DEFAULT_CONCURRENCY = Math.max(1, Number(process.env.REMIFY_CONCURRENCY) || 8);
/** Requests in flight at once per engine, whatever the units and pages ask for (`maxRequests`); the rest queue. */
export const DEFAULT_MAX_REQUESTS = Math.max(1, Number(process.env.REMIFY_MAX_REQUESTS) || 24);

/** A counter that lets `limit` callers through at once and queues the rest in order. */
class Gate {
  #free;
  #waiting = [];

  constructor(limit) {
    this.#free = limit;
  }

  async run(fn) {
    if (this.#free > 0) this.#free -= 1;
    else await new Promise((resolve) => this.#waiting.push(resolve));
    try {
      return await fn();
    } finally {
      const next = this.#waiting.shift();
      if (next) next();
      else this.#free += 1;
    }
  }
}

export class Connector {
  /** The config key and display name, set by each subclass. */
  static id = '';
  static label = '';
  /** Settings the connector needs; `missingSettings` checks they are there. */
  static required = [];
  /** Actions the vendor runs itself: any of 'triage', 'remediate'. */
  static nativeActions = [];

  #auth = { value: null, expiresAt: 0, inFlight: null };
  #gate;

  /**
   * @param {object} config  this engine's block of remify.config.json, variables already filled in
   * @param {{fetchImpl?: typeof fetch, maxFindings?: number, concurrency?: number}} [options]
   */
  constructor(config = {}, { fetchImpl = fetch, maxFindings = Infinity, concurrency } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.maxFindings = maxFindings;
    this.concurrency = Math.max(1, Number(config.concurrency ?? concurrency) || DEFAULT_CONCURRENCY);
    this.#gate = new Gate(Math.max(1, Number(config.maxRequests) || DEFAULT_MAX_REQUESTS));
  }

  get id() {
    return this.constructor.id;
  }

  get label() {
    return this.constructor.label;
  }

  /** The settings that are missing, by name; empty when all are there. */
  missingSettings() {
    return this.constructor.required.filter((key) => {
      const value = this.config[key];
      return value === undefined || value === null || String(value).trim() === '';
    });
  }

  /** One call to the engine, with its auth headers, through the engine's request ceiling. */
  async call(url, options = {}) {
    const headers = { ...(await this.authHeaders()), ...(options.headers ?? {}) };
    return this.#gate.run(() => request(this.label, url, { ...options, headers, fetchImpl: this.fetchImpl }));
  }

  /** The headers that sign a request in; subclasses override. */
  async authHeaders() {
    return {};
  }

  /**
   * A sign-in token, kept until shortly before it expires. However many units
   * ask at once, one sign-in request is made.
   * @param {() => Promise<{value: string, expiresInMs: number}>} signIn
   */
  async token(signIn) {
    const auth = this.#auth;
    if (auth.value && Date.now() < auth.expiresAt) return auth.value;
    auth.inFlight ??= signIn()
      .then(({ value, expiresInMs }) => {
        auth.value = value;
        auth.expiresAt = Date.now() + Math.max(0, Number(expiresInMs) - 60_000);
        return value;
      })
      .finally(() => {
        auth.inFlight = null;
      });
    return auth.inFlight;
  }

  /** Signs in and reads the smallest thing the API has, to prove the connection; answers a one-line description. */
  async check() {
    throw new Error(`${this.label}: check() is not implemented.`);
  }

  /** The work units to read, each with a stable `key`. One unit, by default. */
  async units() {
    return [{ key: 'all' }];
  }

  /** Every finding of one unit, in remify's shape. */
  // eslint-disable-next-line require-yield
  async *unitFindings() {
    throw new Error(`${this.label}: unitFindings() is not implemented.`);
  }

  /**
   * Every unit, `concurrency` at a time. A unit already in the checkpoint is
   * loaded instead of read; a unit read in full is saved to it. A unit that
   * fails is reported with its reason and the others carry on.
   *
   * @param {{checkpoint?: import('./checkpoint.js').Checkpoint, onUnit?: (unit: object) => void}} [options]
   * @returns {Promise<{findings: object[], units: {key: string, ok: boolean, count: number, resumed?: boolean, error?: string}[]}>}
   */
  async readAll({ checkpoint, onUnit } = {}) {
    const units = await this.units();
    const findings = [];
    let budget = this.maxFindings;
    const reports = await mapPool(units, this.concurrency, async (unit) => {
      const key = String(unit.key);
      if (budget <= 0) return { key, ok: true, count: 0, skipped: true };
      const saved = checkpoint?.load(this.id, key);
      if (saved) {
        const taken = saved.slice(0, Math.max(0, budget));
        budget -= taken.length;
        findings.push(...taken);
        const report = { key, ok: true, count: taken.length, resumed: true };
        onUnit?.(report);
        return report;
      }
      const read = [];
      try {
        for await (const finding of this.unitFindings(unit)) {
          read.push(finding);
          if (--budget <= 0) break;
        }
      } catch (error) {
        // What was read is kept for this run but not saved: a resumed run reads the unit again.
        findings.push(...read);
        const report = { key, ok: false, count: read.length, error: error.message };
        onUnit?.(report);
        return report;
      }
      // A unit cut short by maxFindings is not complete, so it is not saved.
      if (budget > 0) checkpoint?.save(this.id, key, read);
      findings.push(...read);
      const report = { key, ok: true, count: read.length };
      onUnit?.(report);
      return report;
    });
    return { findings, units: reports };
  }

  /** Every finding the engine has, for callers that want them all and no report. */
  async *findings() {
    yield* (await this.readAll()).findings;
  }
}
