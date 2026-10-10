import type { ConnectorCandidate, buildConnectorPreview } from "./customer-connector-preview";
import { connectorDraftEvidence, proposal, validateReviewScope, type ConnectorProposal } from "./customer-connector-drafts";
import { connectorDataContract, type ConnectorDomain } from "./connector-data-contracts";

export type CustomerBindingEvidence = {
  id: string; candidateHash: string; importedHash?: string; sourcePresent: boolean;
  reviewState: string; reviewedAt: unknown; proposal: ConnectorProposal;
};
export type ReviewedConnectorScope = { id: string; candidate: ConnectorCandidate; scope: ConnectorProposal; domains: ConnectorDomain[] };
export function checkCustomerConnectorBinding(companyId: string, preview: ReturnType<typeof buildConnectorPreview>, row: CustomerBindingEvidence):
  { ready: true; binding: ReviewedConnectorScope } | { ready: false; reason: string } {
  const fail = (reason: string) => ({ ready: false as const, reason });
  if (!preview.companies.some(c => c.id === companyId) || row.proposal?.companyId !== companyId)
    return fail("The assignment does not belong to this customer.");
  const candidate = preview.candidates.find(c => c.id === row.id);
  if (!candidate || !row.sourcePresent || !candidate.configured) return fail("Source configuration is missing or incomplete.");
  if (candidate.companyId && candidate.companyId !== companyId) return fail("Source ownership has changed; review this assignment.");
  const contract = connectorDataContract(candidate.provider);
  if (!contract || contract.planned) return fail("This source does not have an implemented data adapter.");
  if (candidate.capabilities.some(c => c === "ticket-delivery" || c === "orchestration"))
    return fail("This integration uses its existing routing; it is not a customer findings source.");
  const evidence = connectorDraftEvidence(candidate, preview.candidates);
  if (row.reviewState !== "reviewed" || !row.reviewedAt || row.candidateHash !== evidence.candidateHash ||
      (row.importedHash !== undefined && row.importedHash !== row.candidateHash))
    return fail("This source assignment needs a current review.");
  let scope: ConnectorProposal;
  try { scope = proposal(row.proposal); validateReviewScope(candidate, true, evidence.sourceEvidence, scope); }
  catch { return fail("Resolve the source's customer, tenant, dataset or target scope before use."); }
  let domains: ConnectorDomain[];
  if (scope.authority === "inventory") domains = ["inventory"];
  else if (scope.authority === "enrichment") domains = ["enrichment"];
  else if (scope.authority === "query-only") domains = candidate.capabilities.includes("appsec") ? ["appsec"] : ["saved-queries"];
  else if (scope.authority === "mirror") domains = candidate.capabilities.includes("saved-query") ? ["saved-queries"] :
    contract.domains.filter(domain=>["endpoint-findings","web-findings","exposures"].includes(domain));
  else domains = contract.domains.filter(domain => ["endpoint-findings","web-findings","exposures"].includes(domain));
  if (!domains.length) return fail("This source has no reader for the proposed data role.");
  return { ready: true, binding: { id: candidate.id, candidate, scope, domains } };
}

/** Read routing evidence only. Does not grant scan, query, delivery or import rights.
 * Mirrors have a separate lane and cannot contribute a second findings total.
 */
export function customerConnectorReadPlan(companyId: string, preview: ReturnType<typeof buildConnectorPreview>, rows: CustomerBindingEvidence[]) {
  if (!preview.companies.some(c => c.id === companyId)) throw new Error("Customer not found.");
  if (rows.length > 1000 || new Set(rows.map(row=>row.id)).size !== rows.length) throw new Error("Invalid customer binding set.");
  const bindings: ReviewedConnectorScope[] = [], blocked: { id: string; reason: string }[] = [];
  for (const row of rows) {
    if (row.proposal?.companyId !== companyId || row.reviewState === "dismissed") continue;
    const checked = checkCustomerConnectorBinding(companyId, preview, row);
    if (checked.ready) bindings.push(checked.binding); else blocked.push({ id: row.id, reason: checked.reason });
  }
  // Two reviewed scopes for the same provider/domain require an explicit union
  // contract. Never silently choose the first one or sum duplicate records.
  const conflicts = new Set<string>();
  for (const binding of bindings.filter(b=>b.scope.authority !== "mirror")) {
    for (const domain of binding.domains) {
      if (["saved-queries","appsec","enrichment"].includes(domain)) continue;
      if (bindings.some(other=>other.id !== binding.id && other.candidate.provider === binding.candidate.provider &&
          other.scope.authority !== "mirror" && other.domains.includes(domain))) conflicts.add(binding.id);
    }
  }
  for (const id of conflicts) blocked.push({ id, reason: "Resolve overlapping assignments for this source and data role." });
  return { companyId, bindings: bindings.filter(b=>!conflicts.has(b.id)), blocked, combinedCounts: null, canActivate: false as const };
}
