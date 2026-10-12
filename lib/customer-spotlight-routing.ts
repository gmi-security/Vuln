import { createOperationalRoutingStore, operationalRouteEvidenceSelect } from "./customer-operational-routing";
import { createHash } from "node:crypto";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { type ConnectorProposal } from "./customer-connector-drafts";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";

export type RoutedSpotlightProvider = "crowdstrike";
const providers = ["crowdstrike"];
type Preview = ReturnType<typeof buildConnectorPreview>;
export type SpotlightRoute = { candidateId: string; companyId: string; provider: RoutedSpotlightProvider; sourceScope: string; connectionRef: string; revision: number; bindingRevision: number; candidateHash: string; bindingKey: string };
type RouteRow = {
  candidate_id: string; company_id: string; provider: string; source_scope: string; binding_revision: number;
  candidate_hash: string; revision: number; enabled: boolean;
};
export type SpotlightRouteEvidence = RouteRow & {
  binding_hash: string; imported_hash: string; current_binding_revision: number; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
};
const fail = (message: string): never => { throw new Error(message); };
export function reviewedSpotlightProviders(raw?: string): RoutedSpotlightProvider[] {
  if (!raw?.trim()) return [];
  const selected = raw.split(",").map(s => s.trim());
  if (selected.some(p => !providers.includes(p)) || new Set(selected).size !== selected.length)
    return fail("Invalid reviewed spotlight routing configuration.");
  return selected as RoutedSpotlightProvider[];
}
export function spotlightBindingScope(companyId: string, preview: Preview, row: {
  candidate_id: string; candidate_hash: string; imported_hash: string; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
}) {
  const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
    importedHash: row.imported_hash, proposal: row.proposal, reviewState: row.review_state, reviewedAt: row.reviewed_at, sourcePresent: row.source_present });
  if (!checked.ready) return fail("Spotlight assignment needs a current review.");
  const { candidate, scope } = checked.binding;
  if (candidate.provider !== "crowdstrike" || candidate.evidence !== "environment-match" ||
      !/^environment:FALCON(?:_[2-9][0-9]*|_1[0-9]+)?$/.test(candidate.connectionRef ?? "") ||
      scope.authority !== "findings-primary" || scope.targets.length || scope.datasets.length)
    return fail("Spotlight requires a primary findings assignment for one configured Falcon connection.");
  const tenant = scope.tenantId ?? "";
  if (!/^[a-f0-9]{32}$/i.test(tenant)) return fail("CrowdStrike routing requires the 32-character CID.");
  return { provider: "crowdstrike" as const, sourceScope: tenant.toLowerCase(), connectionRef: candidate.connectionRef! };
}
function validateRoute(row: SpotlightRouteEvidence, preview: Preview): SpotlightRoute {
  if (!row.enabled || row.binding_revision !== row.current_binding_revision || row.candidate_hash !== row.binding_hash)
    return fail("Spotlight route changed or needs renewed approval.");
  const scope = spotlightBindingScope(row.company_id, preview, { ...row, candidate_hash: row.binding_hash });
  if (scope.provider !== row.provider || scope.sourceScope !== row.source_scope)
    return fail("Spotlight route scope no longer matches its assignment.");
  return { candidateId: row.candidate_id, companyId: row.company_id, ...scope, revision: row.revision, bindingRevision: row.binding_revision, candidateHash: row.candidate_hash,
    bindingKey: createHash("sha256").update(JSON.stringify(["spotlight-route-v1", row.candidate_id, row.company_id, scope.connectionRef,
      scope.sourceScope, row.candidate_hash, row.binding_revision, row.revision])).digest("hex") };
}
export const spotlightRouteEvidenceSelect = operationalRouteEvidenceSelect("spotlight");
export type SpotlightRoutingStatus = { id: string; review: string; routing: string };
// Only these fixed labels reach the browser; private scope and audit fields do not.
export function spotlightRoutingStatus(row: SpotlightRouteEvidence, preview: Preview, rawProviders?: string): SpotlightRoutingStatus {
  const id = row.candidate_id;
  if (!row.enabled) return { id, review: "Spotlight route disabled", routing: "This operational approval is disabled. Legacy routing may still apply if the provider switch is off." };
  try {
    const route = validateRoute(row, preview);
    if (!reviewedSpotlightProviders(rawProviders).includes(route.provider))
      return { id, review: "Spotlight route approved", routing: "Approval recorded; the provider routing switch is off. Existing import and saved CVE routing still apply." };
    return { id, review: "Spotlight route approved", routing: "Approved for spotlight routing; the provider switch is on. Imports and saved CVE preparation require current approval. Saved CVEs also require a completed reviewed import; approval alone does not confirm one." };
  } catch { return { id, review: "Spotlight routing needs review", routing: "This approval or provider configuration is stale or invalid. Opted-in imports and saved CrowdStrike CVE preparation stop until it is resolved." }; }
}
export type SpotlightRouteInput = {
  candidateId: string; companyId: string; bindingRevision: number; expectedRevision: number; enabled: boolean; note: string;
};
/** Separate operational approval; reviewing a binding alone never starts routing.
 * No schema initialization, credentials, upstream calls or platform writes.
 */
export function createSpotlightRoutingStore(db: Pick<Pool, "connect">) {
  return createOperationalRoutingStore<RoutedSpotlightProvider, SpotlightRoute>(db, { kind: "spotlight",
    providers: providers as RoutedSpotlightProvider[], bindingScope: spotlightBindingScope, validateRoute,
    checkRoutes(routes, provider) {
      if (new Set(routes.map(r => r.sourceScope)).size !== routes.length) fail("Spotlight source has conflicting customer routes.");
      if (provider === "crowdstrike" && new Set(routes.map(r => r.connectionRef)).size !== routes.length) fail("CrowdStrike connection has conflicting customer routes.");
      if (new Set(routes.map(r => r.companyId)).size !== routes.length) fail("Spotlight customer has conflicting routes.");
    }
  });
}
