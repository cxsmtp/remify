/**
 * What every engine connector is.
 *
 * A connector knows one vendor's API and nothing else: how to sign in, how to
 * check the connection, and how to read every finding it can into remify's
 * shape (src/finding.js). It reads as much as the API gives, every page,
 * because the triage and fix steps are only as good as the context they get.
 *
 * `nativeActions` says what the vendor can do itself, paid for with the
 * customer's own credits there (Checkmarx One AI Triage and Remediation, for
 * one). Anything not listed is done by remify, paid with remify's credits.
 */

import { request } from './http.js';

export class Connector {
  /** The config key and display name, set by each subclass. */
  static id = '';
  static label = '';
  /** Settings the connector needs; `validateConfig` checks they are there. */
  static required = [];
  /** Actions the vendor runs itself: any of 'triage', 'remediate'. */
  static nativeActions = [];

  /**
   * @param {object} config  this engine's block of remify.config.json, variables already filled in
   * @param {{fetchImpl?: typeof fetch, maxFindings?: number}} [options]
   */
  constructor(config = {}, { fetchImpl = fetch, maxFindings = Infinity } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.maxFindings = maxFindings;
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

  /** One call to the engine, with its auth headers. */
  async call(url, options = {}) {
    const headers = { ...(await this.authHeaders()), ...(options.headers ?? {}) };
    return request(this.label, url, { ...options, headers, fetchImpl: this.fetchImpl });
  }

  /** The headers that sign a request in; subclasses override. */
  async authHeaders() {
    return {};
  }

  /** Signs in and reads the smallest thing the API has, to prove the connection; answers a one-line description. */
  async check() {
    throw new Error(`${this.label}: check() is not implemented.`);
  }

  /** Every finding the engine has, in remify's shape. */
  // eslint-disable-next-line require-yield
  async *findings() {
    throw new Error(`${this.label}: findings() is not implemented.`);
  }
}
