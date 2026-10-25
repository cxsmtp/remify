/**
 * The one shape every engine's findings are turned into.
 *
 * Each connector maps its vendor's rows onto `makeFinding`, so the layers
 * above (merging, the AI that makes sense of a finding, and the actions)
 * never see a vendor format. The vendor's own row is kept as `raw` for the
 * context step, which may need a field this shape does not name.
 */

/** What kind of gap a finding is, whichever engine found it. */
export const KINDS = ['sast', 'sca', 'dast', 'iac', 'container', 'secret', 'cloud', 'other'];

/** Severities, worst first. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_WORDS = {
  critical: 'critical',
  crit: 'critical',
  urgent: 'critical',
  high: 'high',
  important: 'high',
  medium: 'medium',
  moderate: 'medium',
  med: 'medium',
  low: 'low',
  minor: 'low',
  info: 'info',
  informational: 'info',
  information: 'info',
  note: 'info',
  none: 'info',
};

/** A vendor's severity word (any case) as one of SEVERITIES; unknown words count as info. */
export function normalizeSeverity(value) {
  return SEVERITY_WORDS[String(value ?? '').trim().toLowerCase()] ?? 'info';
}

/** A CVSS base score as a severity, for engines that give only the number. */
export function severityFromScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return 'info';
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n > 0) return 'low';
  return 'info';
}

/** The worse of two severities. */
export function worstSeverity(a, b) {
  return SEVERITIES.indexOf(a) <= SEVERITIES.indexOf(b) ? a : b;
}

/** "CWE-79", "cwe 79", 79 → 79; anything else → null. */
export function parseCwe(value) {
  const match = String(value ?? '').match(/(\d+)/);
  const n = match ? Number(match[1]) : NaN;
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** The first CVE id in a value, upper-cased, or null. */
export function parseCve(value) {
  const match = String(value ?? '').match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0].toUpperCase() : null;
}

const clean = (value) => (value === undefined || value === '' ? null : value);

/**
 * A finding in remify's shape. Only `engine`, `nativeId`, `kind` and `title`
 * are needed; everything else defaults to null or empty.
 */
export function makeFinding({
  engine,
  nativeId,
  kind,
  title,
  severity = 'info',
  status = 'open',
  cwe = null,
  cve = null,
  asset = {},
  location = {},
  pkg = {},
  endpoint = {},
  description = null,
  remediation = null,
  references = [],
  firstFoundAt = null,
  lastSeenAt = null,
  raw = null,
}) {
  if (!engine || nativeId === undefined || nativeId === null || nativeId === '') {
    throw new Error('A finding needs its engine and the engine\'s own id.');
  }
  return {
    id: `${engine}:${nativeId}`,
    engine,
    nativeId: String(nativeId),
    kind: KINDS.includes(kind) ? kind : 'other',
    title: String(title || 'Untitled finding'),
    severity: SEVERITIES.includes(severity) ? severity : normalizeSeverity(severity),
    status,
    cwe: parseCwe(cwe),
    cve: parseCve(cve),
    asset: {
      project: clean(asset.project),
      repo: clean(asset.repo),
      branch: clean(asset.branch),
      image: clean(asset.image),
      resource: clean(asset.resource),
      url: clean(asset.url),
    },
    location: {
      file: clean(location.file),
      line: Number.isInteger(location.line) && location.line > 0 ? location.line : null,
      dataFlow: Array.isArray(location.dataFlow) ? location.dataFlow : [],
    },
    pkg: {
      name: clean(pkg.name),
      version: clean(pkg.version),
      fixedVersion: clean(pkg.fixedVersion),
      ecosystem: clean(pkg.ecosystem),
    },
    endpoint: {
      url: clean(endpoint.url),
      method: clean(endpoint.method),
      parameter: clean(endpoint.parameter),
    },
    description: clean(description),
    remediation: clean(remediation),
    references: references.filter(Boolean),
    firstFoundAt: clean(firstFoundAt),
    lastSeenAt: clean(lastSeenAt),
    raw,
  };
}
