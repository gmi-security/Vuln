import type { ConnectorCandidate, buildConnectorPreview } from "./customer-connector-preview";
import type { ConnectorProposal } from "./customer-connector-drafts";
import { connectorDraftEvidence } from "./customer-connector-drafts";
import { connectorDataContract } from "./connector-data-contracts";
import { customerConnectorReadPlan } from "./customer-connector-routing";
import type { InventoryRoutingStatus } from "./customer-inventory-routing";

export type ConnectorStatusDraft = {
  id: string; candidate: ConnectorCandidate; candidate_hash: string; proposal: ConnectorProposal;
  source_present: boolean; review_state: string; reviewed_at: string | Date | null;
};
export type CustomerConnectorStatus = {
  companyId: string; companyName: string; checkedAt: string; registryAvailable: boolean;
  items: { id: string; provider: string; evidence: string; configuration: string;
    review: string; reasons: string[]; scope: string; reviewedAt: string | null;
    data?: { domains: readonly string[]; storage: string; lifecycle: string; routing: string } }[];
};
const evidenceNames: Record<string, string> = {
  "saved-binding": "Saved customer connection", "environment-match": "Server configuration",
  "shared-configuration": "Proposed shared connection", "saved-tile": "Saved customer query",
  "completed-import": "Previous completed import",
};
const reviewNames: Record<string, string> = {
  "pending-review": "Pending review", "reviewed": "Reviewed · inactive", "dismissed": "Dismissed · inactive", "needs-review": "Needs review",
};
const reasons: Record<string, string> = {
  "unknown-or-demo-customer": "Customer identity needs verification.",
  "verify-tenant-and-authority": "Verify the vendor tenant and how this source contributes data.",
  "environment-id-needs-review": "The customer ID comes from server configuration and needs review.",
  "name-match-needs-review": "The customer was matched by name; verify this mapping.",
  "customer-not-specified": "No customer is assigned in server configuration.",
  "customer-name-not-found": "The configured customer name was not found.",
  "ambiguous-customer-name": "The configured customer name matches more than one record.",
  "near-duplicate-customer-name": "Similar customer names need review before assignment.",
  "vendor-tenant-not-verified": "The vendor tenant has not been verified.",
  "incomplete-credentials": "Required configuration is incomplete.",
  "legacy-loader-stops-before-this-entry": "A gap in numbered server configuration prevents this entry from loading.",
  "legacy-loader-ignores-without-tenant": "A tenant is required before this configuration can load.",
  "unrecognized-cloud": "The configured cloud region needs correction.",
  "also-present-in-saved-connection": "This also appears in the saved connection; reconcile the two references.",
  "saved-environment-tenant-conflict": "Saved and server-configured tenants disagree.",
  "vendor-tenant-has-multiple-customers": "This vendor tenant has conflicting customer assignments.",
  "customer-target-scope-not-assigned": "Customer-specific targets need verification.",
  "adapter-planned": "This connector adapter is not implemented.",
  "scan-to-customer-mapping-needs-review": "Verify approved targets and scan ownership.",
  "shared-connection-not-a-customer-binding": "Shared configuration alone does not assign a source to this customer.",
  "tile-ownership-is-not-upstream-scope": "Saving a query to a customer does not verify its upstream tenant or dataset.",
  "mirror-authority-needs-review": "Check for mirrored data before combining source totals.",
  "tile-unassigned": "The query has no current customer assignment.",
  "saved-connection-missing": "The saved source connection is missing.",
  "import-pointer-is-not-a-connection": "Previous imported data does not prove a current connection.",
  "app-company-id-is-not-vendor-tenant": "The platform customer ID is not a verified vendor tenant.",
  "current-generation-not-completed": "The recorded import is not confirmed complete.",
  "existing-ticket-routing-required": "Ticket delivery uses the existing customer and board routing. It is not a findings source.",
};

// Public projection: never spread SQL rows, references, raw tenants, target lists,
// audit notes or another customer's candidates into the browser response.
export function customerConnectorStatus(companyId: string, preview: ReturnType<typeof buildConnectorPreview>,
  drafts: ConnectorStatusDraft[], registryAvailable: boolean, checkedAt = new Date().toISOString(), inventory: InventoryRoutingStatus[] = []): CustomerConnectorStatus {
  const company = preview.companies.find(c => c.id === companyId);
  if (!company) throw new Error("Customer not found.");
  const current = new Map(preview.candidates.map(c => [c.id, c]));
  const ownedDrafts = new Map(drafts.filter(d => d.proposal.companyId === companyId).map(d => [d.id, d]));
  const readPlan = customerConnectorReadPlan(companyId, preview, [...ownedDrafts.values()].map(row=>({ id: row.id,
    candidateHash: row.candidate_hash, sourcePresent: row.source_present, reviewState: row.review_state,
    reviewedAt: row.reviewed_at, proposal: row.proposal })));
  const ids = new Set([...preview.candidates.filter(c => c.companyId === companyId).map(c => c.id), ...ownedDrafts.keys()]);
  const items: CustomerConnectorStatus["items"] = [];
  for (const id of ids) {
    const fresh = current.get(id), draft = ownedDrafts.get(id);
    const ownershipChanged = !!draft && !!fresh &&
      (fresh.companyId !== null && fresh.companyId !== companyId || draft.candidate.companyId === companyId && fresh.companyId !== companyId);
    const candidate = ownershipChanged ? draft!.candidate : fresh ?? draft?.candidate;
    if (!candidate) continue;
    const stale = !!draft && (!fresh || !draft.source_present || ownershipChanged ||
      connectorDraftEvidence(fresh, preview.candidates).candidateHash !== draft.candidate_hash);
    const configuration = ownershipChanged ? "Assignment changed" : !fresh ? "No longer recorded" :
      fresh.evidence === "completed-import" ? "Historical evidence" : fresh.companyId === null ? "Proposed assignment" :
        fresh.configured ? "Configuration recorded" : "Configuration incomplete";
    const scope = ownershipChanged ? "Review the previous assignment." : draft
      ? `${draft.proposal.tenantId ? "Tenant recorded" : "Tenant not recorded"} · ${draft.proposal.datasets.length} datasets · ${draft.proposal.targets.length} targets. Proposal remains inactive.`
      : candidate.tenantId ? "Tenant recorded; scope verification pending." : "Customer source scope needs verification.";
    const contract = connectorDataContract(candidate.provider);
    items.push({ id, provider: candidate.provider, evidence: evidenceNames[candidate.evidence] ?? "Source evidence",
      ...(contract ? { data: { domains: contract.domains, storage: contract.storage, lifecycle: contract.lifecycle,
        routing: readPlan.bindings.some(b=>b.id===id) ? "Customer scope reviewed; data-path activation remains disabled." :
          readPlan.blocked.find(b=>b.id===id)?.reason ?? "Customer scope has not been reviewed." } } : {}),
      configuration, review: stale ? "Needs review" : draft ? reviewNames[draft.review_state] ?? "Needs review" : "Not imported for review",
      reasons: ownershipChanged ? ["This proposal no longer matches the current customer assignment. No new owner's details are shown."] :
        [...(stale ? ["Source evidence has changed since the saved review. Refreshing this page does not update or approve the proposal."] : []),
          ...candidate.review.map(code => reasons[code] ?? "Additional source verification is required.")],
      scope, reviewedAt: draft?.reviewed_at ? new Date(draft.reviewed_at).toISOString() : null });
  }
  items.sort((a, b) => a.provider.localeCompare(b.provider) || a.evidence.localeCompare(b.evidence) || a.id.localeCompare(b.id));
  for (const status of inventory) {
    const item = items.find(i => i.id === status.id);
    if (!item || !["automate", "intune", "tidal", "crowdstrike"].includes(item.provider)) continue;
    item.review = status.review;
    item.scope = "A separate inventory import approval is recorded. See routing details for its current state.";
    if (item.data) item.data.routing = status.routing;
  }
  return { companyId, companyName: company.name, checkedAt, registryAvailable, items };
}
