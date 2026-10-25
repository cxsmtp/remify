/**
 * Wiz (cloud, containers, hosts): vulnerability findings and issues, GraphQL.
 *
 *   POST https://auth.app.wiz.io/oauth/token client credentials, audience wiz-api
 *   POST {apiUrl}                            the tenant's endpoint, e.g. https://api.us17.app.wiz.io/graphql
 *     vulnerabilityFindings                  CVEs on images, hosts and serverless, with the fixed version
 *     issuesV2                               toxic combinations and misconfigurations, with the rule's fix
 *
 * Both are cursor pages (pageInfo.endCursor). Only open ones are read unless includeResolved.
 */

import { Connector } from '../connector.js';
import { request } from '../http.js';
import { makeFinding } from '../finding.js';

const PAGE = 500;

export const VULNERABILITIES_QUERY = `query RemifyVulnerabilities($first: Int, $after: String, $filterBy: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id portalUrl name CVEDescription CVSSSeverity score severity status
      firstDetectedAt lastDetectedAt remediation detailedName version fixedVersion locationPath link
      vulnerableAsset {
        ... on VulnerableAssetBase { id type name cloudPlatform providerUniqueId }
        ... on VulnerableAssetContainerImage { imageId }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`;

export const ISSUES_QUERY = `query RemifyIssues($first: Int, $after: String, $filterBy: IssueFilters) {
  issuesV2(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id type severity status createdAt updatedAt
      sourceRule {
        __typename
        ... on Control { id name description resolutionRecommendation }
        ... on CloudConfigurationRule { id name description remediationInstructions }
      }
      entitySnapshot { id type name cloudPlatform region subscriptionExternalId providerId }
    }
    pageInfo { hasNextPage endCursor }
  }
}`;

const STATUS = { RESOLVED: 'fixed', REJECTED: 'accepted', IGNORED: 'accepted' };

export function vulnerabilityToFinding(node) {
  const asset = node.vulnerableAsset ?? {};
  const image = asset.type === 'CONTAINER_IMAGE' || asset.imageId;
  return makeFinding({
    engine: 'wiz',
    nativeId: node.id,
    kind: image ? 'container' : 'cloud',
    title: `${node.name} in ${node.detailedName ?? 'a package'} ${node.version ?? ''}`.trim(),
    severity: node.severity ?? node.CVSSSeverity,
    status: STATUS[node.status] ?? 'open',
    cve: node.name,
    asset: { image: image ? asset.name : null, resource: image ? null : asset.providerUniqueId ?? asset.name, url: node.portalUrl },
    location: { file: node.locationPath },
    pkg: { name: node.detailedName, version: node.version, fixedVersion: node.fixedVersion },
    description: node.CVEDescription,
    remediation: node.remediation ?? (node.fixedVersion ? `Upgrade ${node.detailedName} to ${node.fixedVersion}.` : null),
    references: [node.link, node.portalUrl].filter(Boolean),
    firstFoundAt: node.firstDetectedAt,
    lastSeenAt: node.lastDetectedAt,
    raw: node,
  });
}

export function issueToFinding(node) {
  const rule = node.sourceRule ?? {};
  const entity = node.entitySnapshot ?? {};
  return makeFinding({
    engine: 'wiz',
    nativeId: node.id,
    kind: 'cloud',
    title: rule.name ?? node.type,
    severity: node.severity,
    status: STATUS[node.status] ?? 'open',
    asset: { resource: entity.providerId ?? entity.name, project: entity.subscriptionExternalId },
    description: rule.description,
    remediation: rule.resolutionRecommendation ?? rule.remediationInstructions,
    firstFoundAt: node.createdAt,
    lastSeenAt: node.updatedAt,
    raw: node,
  });
}

export class WizConnector extends Connector {
  static id = 'wiz';
  static label = 'Wiz';
  static required = ['clientId', 'clientSecret', 'apiUrl'];

  #token = null;
  #expiresAt = 0;

  async authHeaders() {
    if (!this.#token || Date.now() >= this.#expiresAt) {
      const answer = await request(this.label, this.config.authUrl || 'https://auth.app.wiz.io/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: this.config.clientId, client_secret: this.config.clientSecret, audience: 'wiz-api' }),
        fetchImpl: this.fetchImpl,
      });
      if (!answer?.access_token) throw new Error('Wiz gave no access token for this service account.');
      this.#token = answer.access_token;
      this.#expiresAt = Date.now() + Number(answer.expires_in ?? 3600) * 1000 - 60_000;
    }
    return { Authorization: `Bearer ${this.#token}` };
  }

  async graphql(query, variables) {
    const answer = await this.call(this.config.apiUrl, { method: 'POST', body: { query, variables } });
    if (answer?.errors?.length) throw new Error(`Wiz: ${answer.errors.map((e) => e.message).join('; ')}`);
    return answer?.data ?? {};
  }

  async *connection(field, query, filterBy) {
    let after = null;
    for (;;) {
      const data = await this.graphql(query, { first: PAGE, after, filterBy });
      const page = data[field] ?? {};
      yield* page.nodes ?? [];
      if (!page.pageInfo?.hasNextPage) return;
      after = page.pageInfo.endCursor;
    }
  }

  async check() {
    const data = await this.graphql(ISSUES_QUERY, { first: 1, filterBy: { status: ['OPEN'] } });
    return `connected, issues readable${data.issuesV2 ? '' : ' (empty)'}`;
  }

  async *findings() {
    const all = Boolean(this.config.includeResolved);
    let count = 0;
    for await (const node of this.connection('vulnerabilityFindings', VULNERABILITIES_QUERY, all ? {} : { status: ['OPEN'] })) {
      yield vulnerabilityToFinding(node);
      if (++count >= this.maxFindings) return;
    }
    for await (const node of this.connection('issuesV2', ISSUES_QUERY, all ? {} : { status: ['OPEN', 'IN_PROGRESS'] })) {
      yield issueToFinding(node);
      if (++count >= this.maxFindings) return;
    }
  }
}
