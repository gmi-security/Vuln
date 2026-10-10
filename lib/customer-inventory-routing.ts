import { createOperationalRoutingStore, operationalRouteEvidenceSelect } from "./customer-operational-routing";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { type ConnectorProposal } from "./customer-connector-drafts";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";

export type RoutedInventoryProvider = "automate" | "intune" | "tidal" | "crowdstrike";
const providers = ["automate", "intune", "tidal", "crowdstrike"];
type Preview = ReturnType<typeof buildConnectorPreview>;
export type InventoryRoute = { candidateId: string; companyId: string; provider: RoutedInventoryProvider; sourceScope: string; connectionRef: string; revision: number };
type RouteRow = {
  candidate_id: string; company_id: string; provider: string; source_scope: string; binding_revision: number;
  candidate_hash: string; revision: number; enabled: boolean;
};
export type InventoryRouteEvidence = RouteRow & {
  binding_hash: string; imported_hash: string; current_binding_revision: number; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
};
const fail = (message: string): never => { throw new Error(message); };
export function reviewedInventoryProviders(raw?: string): RoutedInventoryProvider[] {
  if (!raw?.trim()) return [];
  const selected = raw.split(",").map(s => s.trim());
  if (selected.some(p => !providers.includes(p)) || new Set(selected).size !== selected.length)
    return fail("Invalid reviewed inventory routing configuration.");
  return selected as RoutedInventoryProvider[];
}
export function inventoryBindingScope(companyId: string, preview: Preview, row: {
  candidate_id: string; candidate_hash: string; imported_hash: string; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
}) {
  const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
    importedHash: row.imported_hash, proposal: row.proposal, reviewState: row.review_state, reviewedAt: row.reviewed_at, sourcePresent: row.source_present });
  if (!checked.ready) return fail("Inventory assignment needs a current review.");
  const { candidate, scope } = checked.binding;
  const falcon = candidate.provider === "crowdstrike";
  const connectionValid = falcon ? candidate.evidence === "environment-match" && /^environment:FALCON(?:_[2-9][0-9]*|_1[0-9]+)?$/.test(candidate.connectionRef ?? "") :
    candidate.evidence === "shared-configuration" && candidate.connectionRef === `environment:${candidate.provider}`;
  if (!providers.includes(candidate.provider) || !connectionValid ||
      !(scope.authority === "inventory" || falcon && scope.authority === "findings-primary") || scope.targets.length || scope.datasets.length)
    return fail("This assignment is not supported by the inventory import router.");
  const provider = candidate.provider as RoutedInventoryProvider;
  const tenant = scope.tenantId ?? "";
  if (provider === "automate" && (!/^[1-9][0-9]*$/.test(tenant) || !Number.isSafeInteger(Number(tenant))))
    return fail("Automate routing requires its numeric client ID.");
  if (provider === "intune" && (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(tenant) ||
      tenant.toLowerCase() !== candidate.tenantId?.toLowerCase()))
    return fail("Intune routing requires the configured tenant ID.");
  if (provider === "tidal" && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(tenant))
    return fail("Tidal routing requires its exact company ID.");
  if (falcon && !/^[a-f0-9]{32}$/i.test(tenant)) return fail("CrowdStrike routing requires the 32-character CID.");
  return { provider, sourceScope: provider === "tidal" ? tenant : tenant.toLowerCase(), connectionRef: candidate.connectionRef! };
}
function validateRoute(row: InventoryRouteEvidence, preview: Preview): InventoryRoute {
  if (!row.enabled || row.binding_revision !== row.current_binding_revision || row.candidate_hash !== row.binding_hash)
    return fail("Inventory route changed or needs renewed approval.");
  const scope = inventoryBindingScope(row.company_id, preview, { ...row, candidate_hash: row.binding_hash });
  if (scope.provider !== row.provider || scope.sourceScope !== row.source_scope)
    return fail("Inventory route scope no longer matches its assignment.");
  return { candidateId: row.candidate_id, companyId: row.company_id, ...scope, revision: row.revision };
}
export const inventoryRouteEvidenceSelect = operationalRouteEvidenceSelect("inventory");
export type InventoryRoutingStatus = { id: string; review: string; routing: string };
// Only these fixed labels reach the browser; private scope and audit fields do not.
export function inventoryRoutingStatus(row: InventoryRouteEvidence, preview: Preview, rawProviders?: string): InventoryRoutingStatus {
  const id = row.candidate_id;
  if (!row.enabled) return { id, review: "Inventory route disabled", routing: "This operational approval is disabled. Legacy routing may still apply if the provider switch is off." };
  try {
    const route = validateRoute(row, preview);
    if (!reviewedInventoryProviders(rawProviders).includes(route.provider))
      return { id, review: "Inventory route approved", routing: "Approval recorded; the provider routing switch is off. Existing import routing still applies." };
    return { id, review: "Inventory route approved", routing: "Approved for inventory routing; the provider switch is on. All routes are checked again when an import starts. This does not confirm a successful import." };
  } catch { return { id, review: "Inventory routing needs review", routing: "This approval or provider configuration is stale or invalid. An opted-in import stops until it is resolved." }; }
}
export type InventoryRouteInput = {
  candidateId: string; companyId: string; bindingRevision: number; expectedRevision: number; enabled: boolean; note: string;
};
/** Separate operational approval; reviewing a binding alone never starts routing.
 * No schema initialization, credentials, upstream calls or platform writes.
 */
export function createInventoryRoutingStore(db: Pick<Pool, "connect">) {
  return createOperationalRoutingStore<RoutedInventoryProvider, InventoryRoute>(db, { kind: "inventory",
    providers: providers as RoutedInventoryProvider[], bindingScope: inventoryBindingScope, validateRoute,
    checkRoutes(routes, provider) {
      if (new Set(routes.map(r => r.sourceScope)).size !== routes.length) fail("Inventory source has conflicting customer routes.");
      if (provider === "crowdstrike" && new Set(routes.map(r => r.connectionRef)).size !== routes.length) fail("CrowdStrike connection has conflicting customer routes.");
    }
  });
}
