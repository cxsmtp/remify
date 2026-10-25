import { worstSeverity } from './finding.js';

const lower = (value) => (value === null || value === undefined ? '' : String(value).trim().toLowerCase());

/** A file path as engines would agree on it: forward slashes, no leading slash or "./", lower case. */
export function normalizePath(file) {
  return lower(file).replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, '');
}

/** A repository, image or project name as its last path segment, without .git or a tag. */
export function normalizeAsset(finding) {
  const name = finding.asset.repo || finding.asset.image || '';
  return lower(name).replace(/\.git$/, '').replace(/[:@][^/]*$/, '').split('/').filter(Boolean).at(-1) ?? '';
}

function endpointKey(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return `${parsed.host}${parsed.pathname.replace(/\/+$/, '')}`.toLowerCase();
  } catch {
    return lower(url).replace(/[?#].*$/, '').replace(/\/+$/, '');
  }
}

const weakness = (finding) => (finding.cwe ? `cwe-${finding.cwe}` : lower(finding.title));

/** The key two findings share when they are the same gap; null when the finding cannot be matched. */
export function matchKey(finding) {
  switch (finding.kind) {
    case 'sast':
      return finding.location.file ? `code|${normalizePath(finding.location.file)}|${finding.location.line ?? ''}|${weakness(finding)}` : null;
    case 'secret':
    case 'iac':
      return finding.location.file ? `${finding.kind}|${normalizePath(finding.location.file)}|${finding.location.line ?? ''}` : null;
    case 'sca':
    case 'container':
      return finding.pkg.name ? `pkg|${lower(finding.pkg.name)}|${lower(finding.pkg.version)}|${finding.cve ? lower(finding.cve) : lower(finding.title)}` : null;
    case 'dast': {
      const where = endpointKey(finding.endpoint.url || finding.asset.url);
      return where ? `dast|${where}|${lower(finding.endpoint.parameter)}|${weakness(finding)}` : null;
    }
    case 'cloud':
      return finding.asset.resource ? `cloud|${lower(finding.asset.resource)}|${finding.cve ? lower(finding.cve) : lower(finding.title)}` : null;
    default:
      return null;
  }
}

/** Split one key's findings by asset: named assets apart, unnamed ones with the biggest named group. */
function splitByAsset(findings) {
  const byAsset = new Map();
  const unnamed = [];
  for (const finding of findings) {
    const asset = normalizeAsset(finding);
    if (!asset) unnamed.push(finding);
    else byAsset.set(asset, [...(byAsset.get(asset) ?? []), finding]);
  }
  if (byAsset.size === 0) return [unnamed];
  const groups = [...byAsset.values()].sort((a, b) => b.length - a.length);
  groups[0].push(...unnamed);
  return groups;
}

function toIssue(key, findings) {
  const severity = findings.reduce((worst, f) => worstSeverity(worst, f.severity), 'info');
  const lead = findings.find((f) => f.severity === severity) ?? findings[0];
  const engines = [...new Set(findings.map((f) => f.engine))].sort();
  return {
    key,
    kind: lead.kind,
    title: lead.title,
    severity,
    cwe: findings.find((f) => f.cwe)?.cwe ?? null,
    cve: findings.find((f) => f.cve)?.cve ?? null,
    engines,
    corroborated: engines.length > 1,
    reports: findings.length,
    findings,
  };
}

/**
 * Merge findings into issues, worst first. Findings that are already fixed,
 * accepted or not exploitable in their engine are left out unless includeClosed.
 */
export function mergeFindings(findings, { includeClosed = false } = {}) {
  const open = includeClosed ? findings : findings.filter((f) => f.status === 'open');
  const byKey = new Map();
  const issues = [];
  for (const finding of open) {
    const key = matchKey(finding);
    if (!key) {
      issues.push(toIssue(`id|${finding.id}`, [finding]));
      continue;
    }
    byKey.set(key, [...(byKey.get(key) ?? []), finding]);
  }
  for (const [key, group] of byKey) {
    const parts = splitByAsset(group);
    parts.forEach((part, i) => issues.push(toIssue(parts.length > 1 ? `${key}|${i}` : key, part)));
  }
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  return issues.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || b.engines.length - a.engines.length);
}

/** Counts for one line of output: how many findings became how many issues, and how many more than one engine confirms. */
export function summarize(findings, issues) {
  const bySeverity = {};
  for (const issue of issues) bySeverity[issue.severity] = (bySeverity[issue.severity] ?? 0) + 1;
  return {
    findings: findings.length,
    open: issues.reduce((n, issue) => n + issue.reports, 0),
    issues: issues.length,
    corroborated: issues.filter((issue) => issue.corroborated).length,
    bySeverity,
  };
}
