export const ssrf = {
  type: 'sast',
  id: 'I1ZRUsG8QTqktyAPlZSWsQQn+sc=',
  similarityId: '1475124687',
  status: 'RECURRENT',
  state: 'CONFIRMED',
  severity: 'HIGH',
  firstFoundAt: '2026-10-03T15:45:48Z',
  foundAt: '2026-10-24T23:30:08Z',
  description: '',
  data: {
    queryName: 'Server-Side Request Forgery (SSRF)',
    group: 'JavaScript_HIGH',
    languageName: 'JavaScript',
    nodes: [
      { fileName: '/src/cxone/endpoints.js', line: 180, column: 9, method: 'export function deriveConnection(apiKey, overrides = {}) {', name: 'claims' },
      { fileName: '/src/cxone/endpoints.js', line: 220, column: 5, method: 'export function deriveConnection(apiKey, overrides = {}) {', name: 'tokenUrl' },
      { fileName: '/src/cxone/auth.js', line: 71, column: 24, method: 'async #fetchToken() {', name: 'fetch' },
    ],
  },
  vulnerabilityDetails: { cweId: 918, compliances: ['OWASP Top 10 2021'] },
};

export const secret = {
  type: 'sscs-secret-detection',
  id: '4GICuC6zsMrZXYznoknnesA0qZiSmYvSbPvpA-tiVYE',
  similarityId: 'b2d048d7f624f44845352cdc201cd07ffdc15ef3942addc3b7c4eca556aa6514',
  status: 'RECURRENT',
  state: 'TO_VERIFY',
  severity: 'CRITICAL',
  firstFoundAt: '2026-10-24T18:06:26Z',
  foundAt: '2026-10-24T23:27:53Z',
  description: 'Generic-Api-Key has detected secret for file /test/connection-guard.e2e.test.js.',
  data: {
    ruleName: 'Generic-Api-Key',
    ruleDescription: 'Detected a Generic API Key, potentially exposing access to various services and sensitive operations.',
    fileName: '/test/connection-guard.e2e.test.js',
    line: 157,
    snippet: '0f8f***',
    remediation: 'Remove api-key 0f8f*** from source control and store it in your organization’s secret manager.',
    remediationAdditional: 'Retrieve it at runtime through environment variables. Make sure to rotate/revoke the exposed secret.',
    validity: 'Unknown',
  },
  vulnerabilityDetails: {},
};

/** The same critical, reported with ten different similarity ids at one line. */
export const missingAuth = Array.from({ length: 10 }, (_, i) => ({
  type: 'sast',
  id: `missing-auth-${i}`,
  similarityId: String(1000 + i),
  status: 'RECURRENT',
  state: i === 4 ? 'PROPOSED_NOT_EXPLOITABLE' : 'TO_VERIFY',
  severity: 'CRITICAL',
  data: {
    queryName: 'Missing Authentication for Critical Function',
    languageName: 'JavaScript',
    nodes: [
      { fileName: '/loadtest/mock-cxone.mjs', line: 154, column: 13, method: "req.on('end', () => {", name: 'u' },
      { fileName: '/loadtest/mock-cxone.mjs', line: 161, column: 49, method: "req.on('end', () => {", name: 'REFUSE_SETTING' },
    ],
  },
  vulnerabilityDetails: { cweId: 306 },
}));

export const lodash = {
  type: 'sca',
  id: 'sca-lodash-1',
  severity: 'HIGH',
  state: 'TO_VERIFY',
  status: 'NEW',
  description: 'Prototype pollution in lodash.',
  data: { packageIdentifier: 'Npm-lodash-4.17.20', recommendedVersion: '4.17.21' },
  vulnerabilityDetails: { cveName: 'CVE-2021-23337', cweId: 94 },
};

/** A fake API key: a JWT whose iss names the EU realm "acme". */
export function fakeApiKey(iss = 'https://eu.iam.checkmarx.net/auth/realms/acme') {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'none' })}.${part({ iss })}.sig`;
}
