const RETRYABLE = new Set([429, 502, 503, 504]);
const REQUEST_TIMEOUT_MS = Math.max(5_000, Number(process.env.REMIFY_REQUEST_TIMEOUT_MS) || 60_000);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class EngineError extends Error {
  constructor(message, { engine = '', status = 0, url = '', body = '' } = {}) {
    super(message);
    this.name = 'EngineError';
    this.engine = engine;
    this.status = status;
    this.url = url;
    this.body = body;
  }
}

/** "fetch failed" says nothing: name the network reason (timeout, DNS, TLS, refused…). */
export function networkReason(error) {
  if (error?.name === 'TimeoutError' || error?.name === 'AbortError') return `no answer within ${Math.round(REQUEST_TIMEOUT_MS / 1000)} s`;
  const code = error?.cause?.code || error?.code || '';
  const known = {
    ENOTFOUND: 'host name not found (DNS)',
    EAI_AGAIN: 'DNS lookup failed temporarily',
    ECONNREFUSED: 'connection refused',
    ECONNRESET: 'connection reset',
    ETIMEDOUT: 'connection timed out',
    UND_ERR_CONNECT_TIMEOUT: 'connection timed out',
    CERT_HAS_EXPIRED: 'TLS certificate expired',
    SELF_SIGNED_CERT_IN_CHAIN: 'its certificate is not trusted here (usually a company proxy that inspects HTTPS)',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'its certificate is not trusted here (usually a company proxy that inspects HTTPS)',
  };
  return known[code] || [code, error?.cause?.message || error?.message].filter(Boolean).join(': ') || 'network error';
}

/**
 * One request to an engine. `body` that is not a string or URLSearchParams is
 * sent as JSON. Answers JSON when the engine does, else text.
 *
 * @param {string} engine  the engine's name, for error messages
 * @param {string} url
 * @param {{method?: string, headers?: object, query?: object, body?: any, retries?: number, fetchImpl?: typeof fetch}} [options]
 */
export async function request(engine, url, { method = 'GET', headers = {}, query, body, retries = 2, fetchImpl = fetch } = {}) {
  const target = new URL(url);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === '') continue;
    for (const one of [].concat(value)) target.searchParams.append(key, String(one));
  }

  const init = { method, headers: { Accept: 'application/json', ...headers } };
  if (body !== undefined) {
    if (typeof body === 'string' || body instanceof URLSearchParams) {
      init.body = body;
    } else {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] ??= 'application/json';
    }
  }

  for (let attempt = 0; ; attempt += 1) {
    let response;
    try {
      response = await fetchImpl(target, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    } catch (error) {
      if (attempt < retries) {
        await sleep(500 * 2 ** attempt);
        continue;
      }
      throw new EngineError(`Could not reach ${engine} at ${target.host}: ${networkReason(error)}.`, { engine, url: target.href });
    }

    if (RETRYABLE.has(response.status) && attempt < retries) {
      const wait = Number(response.headers.get('retry-after'));
      await sleep(Number.isFinite(wait) && wait > 0 ? Math.min(wait, 30) * 1000 : 500 * 2 ** attempt);
      continue;
    }

    const text = await response.text();
    if (!response.ok) {
      const hint = response.status === 401 || response.status === 403 ? ' The credentials are wrong, expired or lack the needed scope.' : '';
      throw new EngineError(`${engine} answered ${response.status} ${response.statusText} for ${target.pathname}.${hint}`, {
        engine,
        status: response.status,
        url: target.href,
        body: text.slice(0, 500),
      });
    }
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
}
