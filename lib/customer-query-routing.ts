import { elasticDatasets } from "./customer-elastic-scope";
import { createHash } from "node:crypto";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import type { SpotlightRouteEvidence } from "./customer-spotlight-routing";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";
import { createOperationalRoutingStore, operationalRouteEvidenceSelect } from "./customer-operational-routing";

type Preview = ReturnType<typeof buildConnectorPreview>;
export type QueryRoute = { candidateId: string; companyId: string; provider: QueryProvider; sourceScope: string;
  connectionRef: string; connectionRevision: number; revision: number; bindingRevision: number; bindingKey: string };
export type QueryProvider = "crowdstrike" | "elastic";
export function reviewedQueryRouting(raw?: string, provider: QueryProvider = "crowdstrike"): boolean {
  if (!raw?.trim()) return false;
  const names = raw.split(",").map(s => s.trim());
  if (names.some(s => !["crowdstrike", "elastic"].includes(s)) || new Set(names).size !== names.length)
    throw new Error("Invalid reviewed query routing configuration.");
  return names.includes(provider);
}
export function queryBindingScope(companyId: string, preview: Preview, row: SpotlightRouteEvidence) {
  const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
    importedHash: row.imported_hash, sourcePresent: row.source_present, reviewState: row.review_state, reviewedAt: row.reviewed_at, proposal: row.proposal });
  if (!checked.ready) throw new Error("Query source assignment needs a current review.");
  const { candidate, scope } = checked.binding;
  if (candidate.provider === "elastic") {
    if (candidate.evidence !== "shared-configuration" || candidate.connectionRef !== "dashboard:elastic_dashboard_connection:1" ||
        scope.authority !== "query-only" || scope.tenantId || scope.targets.length || !candidate.revision)
      throw new Error("Elastic query routing requires the saved connection and exclusive exact datasets with query-only authority.");
    return { provider: "elastic" as const, sourceScope: JSON.stringify(elasticDatasets(scope.datasets)),
      connectionRef: candidate.connectionRef, connectionRevision: candidate.revision };
  }
  if (candidate.provider !== "crowdstrike" || candidate.evidence !== "shared-configuration" ||
      candidate.connectionRef !== "dashboard:dashboard_source_connections:crowdstrike" ||
      scope.authority !== "query-only" || scope.targets.length || scope.datasets.length ||
      !/^[a-f0-9]{32}$/i.test(scope.tenantId ?? "") || !candidate.revision)
    throw new Error("Query routing requires the saved CrowdStrike connection, one verified CID and query-only authority without extra filters.");
  return { provider: "crowdstrike" as const, sourceScope: scope.tenantId!.toLowerCase(), connectionRef: candidate.connectionRef,
    connectionRevision: candidate.revision };
}
function validateRoute(row: SpotlightRouteEvidence, preview: Preview): QueryRoute {
  if (!row.enabled || row.binding_revision !== row.current_binding_revision || row.candidate_hash !== row.binding_hash)
    throw new Error("Query route changed or needs renewed approval.");
  const scope = queryBindingScope(row.company_id, preview, { ...row, candidate_hash: row.binding_hash });
  if (row.provider !== scope.provider || row.source_scope !== scope.sourceScope) throw new Error("Query route scope changed.");
  return { ...scope, candidateId: row.candidate_id, companyId: row.company_id, revision: row.revision, bindingRevision: row.binding_revision,
    bindingKey: createHash("sha256").update(JSON.stringify(["query-route-v1", row.candidate_id, row.company_id, row.candidate_hash,
      row.binding_revision, row.revision, scope.sourceScope, scope.connectionRevision])).digest("hex") };
}
export const queryRouteEvidenceSelect = operationalRouteEvidenceSelect("query");
export function createQueryRoutingStore(db: Pick<Pool, "connect">) {
  return createOperationalRoutingStore<QueryProvider, QueryRoute>(db, { kind: "query", providers: ["crowdstrike", "elastic"],
    bindingScope: queryBindingScope, validateRoute, validatePeersOnSave: true,
    checkRoutes(routes) {
      if (new Set(routes.map(r => r.companyId)).size !== routes.length) throw new Error("Query customer/source ownership conflicts.");
      const owned = new Set<string>();
      for (const route of routes) {
        const names = route.provider === "elastic" ? elasticDatasets(JSON.parse(route.sourceScope)) : [route.sourceScope];
        for (const name of names) {
          if (owned.has(name)) throw new Error("Query customer/source ownership conflicts.");
          owned.add(name);
        }
      }
    } });
}
export function queryRoutingStatus(row: SpotlightRouteEvidence, preview: Preview, raw?: string) {
  if (!row.enabled) return { id: row.candidate_id, review: "Query route disabled", routing: "This query approval is disabled. Legacy routing may apply when the provider switch is off." };
  try { validateRoute(row, preview); return { id: row.candidate_id, review: "Query route approved", routing: reviewedQueryRouting(raw, row.provider as QueryProvider) ?
    "Customer-scoped query routing is on. Results and patch collection recheck this approval; this does not confirm source health." :
    "Approval recorded; the query routing switch is off. Existing query behavior still applies." }; }
  catch { return { id: row.candidate_id, review: "Query routing needs review", routing: "Current source/customer approval is unavailable. Reviewed queries and new patch collection are withheld." }; }
}
