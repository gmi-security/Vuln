import type { Pool } from "pg";
import { readApplicationConnectorMetadata } from "./db/connector-metadata.mjs";
import { buildConnectorPreview } from "./customer-connector-preview";
import type { ConnectorProposal } from "./customer-connector-drafts";
import { SavedSourceError, type SavedSource, type SavedSourceSelection } from "./customer-saved-sources";
import { checkCustomerConnectorBinding } from "./customer-connector-routing";

type BindingRow = {
  candidate_id: string; candidate_hash: string; imported_hash: string;
  proposal: ConnectorProposal; review_state: string; reviewed_at: unknown; source_present: boolean;
  provider: string;
};

/** Selects separate saved-result previews, not platform authority or ingest routing.
 * Review alone never proves that an adapter enforces a proposed tenant/filter.
 */
export function selectSavedSourceBindings(companyId: string, preview: ReturnType<typeof buildConnectorPreview>, rows: BindingRow[]): SavedSourceSelection {
  if (!preview.companies.some(c => c.id === companyId)) throw new SavedSourceError("Customer not found.", 404);
  const result: SavedSourceSelection = { sources: [], blocked: [] };
  for (const source of ["defender", "crowdstrike"] as SavedSource[]) {
    const assignments = rows.filter(row => row.provider === source && row.review_state !== "dismissed");
    if (!assignments.length) continue;
    const block = (reason: string) => result.blocked.push({ source, reason });
    // More than one endpoint assignment cannot silently choose between tenants,
    // or combine a mirror with a primary. Inventory-only bindings do not route findings.
    const findings = assignments.filter(row => !["inventory", "enrichment", "query-only"].includes(row.proposal?.authority));
    if (!findings.length) continue;
    if (findings.length !== 1) { block("Resolve overlapping source assignments before viewing saved findings."); continue; }
    const row = findings[0];
    const checked = checkCustomerConnectorBinding(companyId, preview, { id: row.candidate_id, candidateHash: row.candidate_hash,
      importedHash: row.imported_hash, sourcePresent: row.source_present, reviewState: row.review_state, reviewedAt: row.reviewed_at, proposal: row.proposal });
    if (!checked.ready || checked.binding.candidate.provider !== source) {
      block("This source assignment needs a current review."); continue;
    }
    const { candidate, scope } = checked.binding;
    if (scope.authority !== "findings-primary") {
      block("Mirrored findings are not selected as an independent saved source."); continue;
    }
    // The existing adapters read a full saved customer generation. They cannot
    // enforce additional dataset or target filters supplied by an assignment.
    if (scope.datasets.length || scope.targets.length) {
      block("This saved reader cannot enforce the assignment's additional filters."); continue;
    }
    if (source === "crowdstrike") {
      if (candidate.evidence !== "environment-match" || candidate.companyId !== companyId ||
          !candidate.capabilities.includes("vulnerability-import") || !scope.tenantId || !/^[a-f0-9]{32}$/i.test(scope.tenantId)) {
        block("Review the customer's Falcon connection and vendor CID before viewing saved findings."); continue;
      }
      result.sources.push(source); result.spotlightTenant = scope.tenantId.toLowerCase(); continue;
    }
    if (candidate.evidence !== "saved-binding" || candidate.companyId !== companyId ||
        candidate.connectionRef !== `application:defender_connections:${companyId}` ||
        !candidate.tenantId || !candidate.revision || scope.tenantId !== candidate.tenantId) {
      block("Review the saved Defender connection for this customer before viewing its findings."); continue;
    }
    result.sources.push(source);
    result.defenderConnection = { tenantId: candidate.tenantId, revision: candidate.revision };
  }
  return result;
}

/** Bounded metadata reads only. No schema initialization, credentials, API calls,
 * finding hydration or fallback to the legacy environment allowlist.
 */
export function createSavedSourceBindingSelector(db: Pick<Pool, "connect">, env: Partial<NodeJS.ProcessEnv>) {
  return async (companyId: string): Promise<SavedSourceSelection> => {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId)) throw new SavedSourceError("Choose an existing customer.", 400);
    const client = await db.connect();
    try {
      const metadata = await readApplicationConnectorMetadata(client);
      // Dashboard query bindings are intentionally not endpoint source readers.
      const preview = buildConnectorPreview({ ...metadata, connections: [], tiles: [] }, env);
      if (!preview.companies.some(c => c.id === companyId)) throw new SavedSourceError("Customer not found.", 404);
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      try {
        await client.query("SET LOCAL statement_timeout='15s'");
        await client.query("SET LOCAL lock_timeout='2s'");
        await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
        const installed = (await client.query(`SELECT to_regclass('public.customer_connector_bindings') IS NOT NULL
          AND to_regclass('public.customer_connector_drafts') IS NOT NULL AS ready`)).rows[0]?.ready;
        if (!installed) throw new SavedSourceError("Customer source assignments have not been installed.", 503);
        const rows = (await client.query(`SELECT b.candidate_id,b.candidate_hash,b.proposal,b.review_state,b.reviewed_at,
          d.candidate_hash AS imported_hash,d.source_present,d.candidate->>'provider' AS provider
          FROM public.customer_connector_bindings b JOIN public.customer_connector_drafts d ON d.id=b.candidate_id
          WHERE b.company_id=$1 ORDER BY b.candidate_id LIMIT 1001`, [companyId])).rows as BindingRow[];
        if (rows.length > 1000) throw new SavedSourceError("Too many customer source assignments.", 503);
        const result = selectSavedSourceBindings(companyId, preview, rows);
        await client.query("COMMIT");
        return result;
      } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
    } finally { client.release(); }
  };
}
