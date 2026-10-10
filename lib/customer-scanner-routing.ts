import { scannerTargetMatcher } from "./scanner-target-scope";
import { createOperationalRoutingStore, operationalRouteEvidenceSelect } from "./customer-operational-routing";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { type ConnectorProposal } from "./customer-connector-drafts";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";

export type RoutedScannerProvider = "nessus";
const providers = ["nessus"];
type Preview = ReturnType<typeof buildConnectorPreview>;
export type ScannerRoute = { candidateId: string; companyId: string; provider: RoutedScannerProvider; sourceScope: string; connectionRef: string; revision: number; bindingRevision: number; targets: string[] };
type RouteRow = {
  candidate_id: string; company_id: string; provider: string; source_scope: string; binding_revision: number;
  candidate_hash: string; revision: number; enabled: boolean;
};
export type ScannerRouteEvidence = RouteRow & {
  binding_hash: string; imported_hash: string; current_binding_revision: number; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
};
const fail = (message: string): never => { throw new Error(message); };
export function reviewedScannerProviders(raw?: string): RoutedScannerProvider[] {
  if (!raw?.trim()) return [];
  const selected = raw.split(",").map(s => s.trim());
  if (selected.some(p => !providers.includes(p)) || new Set(selected).size !== selected.length)
    return fail("Invalid reviewed scanner routing configuration.");
  return selected as RoutedScannerProvider[];
}
export function scannerBindingScope(companyId: string, preview: Preview, row: {
  candidate_id: string; candidate_hash: string; imported_hash: string; proposal: ConnectorProposal;
  review_state: string; reviewed_at: unknown; source_present: boolean;
}) {
  const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
    importedHash: row.imported_hash, proposal: row.proposal, reviewState: row.review_state, reviewedAt: row.reviewed_at, sourcePresent: row.source_present });
  if (!checked.ready) return fail("Scanner assignment needs a current review.");
  const { candidate, scope } = checked.binding;
  if (candidate.provider !== "nessus" || candidate.evidence !== "shared-configuration" ||
      candidate.connectionRef !== "environment:scanner:nessus" || scope.authority !== "findings-primary" || scope.datasets.length)
    return fail("Scanner routing requires a primary findings assignment for the configured Nessus scanner.");
  const folderId = scope.tenantId ?? "";
  if (!/^[1-9][0-9]*$/.test(folderId) || !Number.isSafeInteger(Number(folderId)))
    return fail("Nessus routing requires its numeric folder ID.");
  scannerTargetMatcher(scope.targets);
  return { provider: "nessus" as const, sourceScope: folderId, connectionRef: candidate.connectionRef, targets: scope.targets };

}
function validateRoute(row: ScannerRouteEvidence, preview: Preview): ScannerRoute {
  if (!row.enabled || row.binding_revision !== row.current_binding_revision || row.candidate_hash !== row.binding_hash)
    return fail("Scanner route changed or needs renewed approval.");
  const scope = scannerBindingScope(row.company_id, preview, { ...row, candidate_hash: row.binding_hash });
  if (scope.provider !== row.provider || scope.sourceScope !== row.source_scope)
    return fail("Scanner route scope no longer matches its assignment.");
  return { candidateId: row.candidate_id, companyId: row.company_id, ...scope, revision: row.revision, bindingRevision: row.binding_revision };
}
export const scannerRouteEvidenceSelect = operationalRouteEvidenceSelect("scanner");
export type ScannerRoutingStatus = { id: string; review: string; routing: string };
// Only these fixed labels reach the browser; private scope and audit fields do not.
export function scannerRoutingStatus(row: ScannerRouteEvidence, preview: Preview, rawProviders?: string): ScannerRoutingStatus {
  const id = row.candidate_id;
  if (!row.enabled) return { id, review: "Scanner route disabled", routing: "This operational approval is disabled. Legacy routing may still apply if the provider switch is off." };
  try {
    const route = validateRoute(row, preview);
    if (!reviewedScannerProviders(rawProviders).includes(route.provider))
      return { id, review: "Scanner route approved", routing: "Approval recorded; the provider routing switch is off. Existing import routing still applies." };
    return { id, review: "Scanner route approved", routing: "Approved for scanner routing; the provider switch is on. All routes are checked again when an import starts. This does not confirm a successful import." };
  } catch { return { id, review: "Scanner routing needs review", routing: "This approval or provider configuration is stale or invalid. An opted-in import stops until it is resolved." }; }
}
export type ScannerRouteInput = {
  candidateId: string; companyId: string; bindingRevision: number; expectedRevision: number; enabled: boolean; note: string;
};
/** Separate operational approval; reviewing a binding alone never starts routing.
 * No schema initialization, credentials, upstream calls or platform writes.
 */
export function createScannerRoutingStore(db: Pick<Pool, "connect">) {
  return createOperationalRoutingStore<RoutedScannerProvider, ScannerRoute>(db, { kind: "scanner",
    providers: providers as RoutedScannerProvider[], bindingScope: scannerBindingScope, validateRoute,
    checkRoutes(routes, provider) {
      if (new Set(routes.map(r => r.sourceScope)).size !== routes.length) fail("Scanner source has conflicting customer routes.");

    }
  });
}
