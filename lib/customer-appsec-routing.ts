import { createHash } from "node:crypto";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import type { SpotlightRouteEvidence } from "./customer-spotlight-routing";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";
import { createOperationalRoutingStore, operationalRouteEvidenceSelect } from "./customer-operational-routing";
import { elasticDatasets } from "./customer-elastic-scope";

type Preview = ReturnType<typeof buildConnectorPreview>;
type Env = Record<string, string | undefined>;
export type AppSecRoute = { candidateId: string; companyId: string; provider: "appsec"; sourceScope: string;
  repositories: string[]; datasets: string[]; connectionRevision: number; revision: number; bindingKey: string };
export function reviewedAppSecRouting(raw?: string) {
  if (!raw?.trim()) return false;
  if (raw.trim() !== "appsec") throw new Error("Invalid reviewed AppSec routing configuration.");
  return true;
}
export function appsecStreams(env: Env) {
  const scan = env.APPSEC_ELASTIC_SCAN_STREAM?.trim() || "gmi-appsec-scans";
  const finding = env.APPSEC_ELASTIC_FINDING_STREAM?.trim() || "gmi-appsec-findings";
  return { scan, finding, datasets: elasticDatasets([scan, finding]) };
}
export function appsecRepositories(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 100 || value.some(v => typeof v !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v) || /\/(?:\.|\.\.)$/.test(v)) ||
      new Set(value.map(v => v.toLowerCase())).size !== value.length)
    throw new Error("AppSec routing requires exact owner/repository identities, with no wildcard or duplicate repository.");
  return [...value].sort();
}
export function appsecBindingScope(companyId: string, preview: Preview, row: SpotlightRouteEvidence, env: Env) {
  const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
    importedHash: row.imported_hash, sourcePresent: row.source_present, reviewState: row.review_state, reviewedAt: row.reviewed_at, proposal: row.proposal });
  if (!checked.ready) throw new Error("AppSec assignment needs a current review.");
  const { candidate, scope } = checked.binding, streams = appsecStreams(env);
  if (candidate.provider !== "appsec" || candidate.evidence !== "shared-configuration" || candidate.connectionRef !== "environment:appsec" ||
      scope.authority !== "query-only" || scope.tenantId || !candidate.revision ||
      JSON.stringify(elasticDatasets(scope.datasets)) !== JSON.stringify(streams.datasets))
    throw new Error("AppSec routing requires the configured scan/finding datasets and query-only repository ownership.");
  const repositories = appsecRepositories(scope.targets);
  // One shared environment source: a repository cannot be assigned twice even
  // when operators use different casing or a previous stream configuration.
  return { provider: "appsec" as const, sourceScope: JSON.stringify(repositories.map(v => v.toLowerCase()).sort()),
    datasets: streams.datasets, repositories, connectionRevision: candidate.revision };
}
function validateRoute(row: SpotlightRouteEvidence, preview: Preview, env: Env): AppSecRoute {
  if (!row.enabled || row.binding_revision !== row.current_binding_revision || row.candidate_hash !== row.binding_hash)
    throw new Error("AppSec route changed or needs renewed approval.");
  const scope = appsecBindingScope(row.company_id, preview, { ...row, candidate_hash: row.binding_hash }, env);
  if (row.provider !== scope.provider || row.source_scope !== scope.sourceScope) throw new Error("AppSec route scope changed.");
  return { ...scope, candidateId: row.candidate_id, companyId: row.company_id, revision: row.revision,
    bindingKey: createHash("sha256").update(JSON.stringify(["appsec-route-v1", row.candidate_id, row.company_id, row.binding_hash,
      row.binding_revision, row.revision, scope.repositories, scope.datasets, scope.connectionRevision])).digest("hex") };
}
export const appsecRouteEvidenceSelect = operationalRouteEvidenceSelect("appsec");
export function createAppSecRoutingStore(db: Pick<Pool, "connect">, env: Env = process.env) {
  return createOperationalRoutingStore<"appsec", AppSecRoute>(db, { kind: "appsec", providers: ["appsec"], validatePeersOnSave: true,
    bindingScope: (company, preview, row) => appsecBindingScope(company, preview, row, env),
    validateRoute: (row, preview) => validateRoute(row, preview, env),
    checkRoutes(routes) {
      const repos = routes.flatMap(route => route.repositories.map(repo => repo.toLowerCase()));
      if (new Set(routes.map(r => r.companyId)).size !== routes.length || new Set(repos).size !== repos.length)
        throw new Error("AppSec repository ownership conflicts.");
    } });
}
export function appsecRoutingStatus(row: SpotlightRouteEvidence, preview: Preview, env: Env) {
  if (!row.enabled) return { id: row.candidate_id, review: "AppSec route disabled", routing: "This approval is disabled. The organization view remains available only when reviewed routing is off." };
  try {
    validateRoute(row, preview, env);
    return { id: row.candidate_id, review: "AppSec route approved", routing: reviewedAppSecRouting(env.VULN_REVIEWED_APPSEC_PROVIDERS)
      ? "Customer repository routing is on. Reads recheck approval; this does not verify live source health or publish device findings."
      : "Approval recorded; the AppSec routing switch is off. Existing organization-wide reads still apply." };
  } catch { return { id: row.candidate_id, review: "AppSec routing needs review", routing: "Current source or repository approval is unavailable. Reviewed AppSec reads are withheld." }; }
}
