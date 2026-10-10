import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { validatePreview, type ConnectorProposal } from "./customer-connector-drafts";
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
export const inventoryRouteEvidenceSelect = `SELECT r.*,b.candidate_hash AS binding_hash,b.revision AS current_binding_revision,
  b.proposal,b.review_state,b.reviewed_at,d.candidate_hash AS imported_hash,d.source_present
  FROM public.customer_inventory_routes r
  LEFT JOIN public.customer_connector_bindings b ON b.candidate_id=r.candidate_id AND b.company_id=r.company_id
  LEFT JOIN public.customer_connector_drafts d ON d.id=r.candidate_id`;
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
  async function save(input: InventoryRouteInput, actor: string, collect: () => Promise<Preview>) {
    const keys = ["candidateId", "companyId", "bindingRevision", "expectedRevision", "enabled", "note"];
    if (!input || Object.keys(input).length !== keys.length || Object.keys(input).some(k => !keys.includes(k)) ||
        !/^[a-f0-9]{64}$/.test(input.candidateId) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(input.companyId) ||
        !Number.isSafeInteger(input.bindingRevision) || input.bindingRevision < 1 || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0 ||
        typeof input.enabled !== "boolean" || typeof input.note !== "string" || !input.note.trim() || input.note.length > 1000 || /[\x00-\x1f\x7f]/.test(input.note) ||
        typeof actor !== "string" || !actor || actor.length > 160 || /[\x00-\x1f\x7f]/.test(actor))
      return fail("Invalid inventory routing approval.");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SELECT pg_advisory_xact_lock(716301,1)");
      const before: RouteRow | undefined = (await client.query(`SELECT * FROM public.customer_inventory_routes
        WHERE candidate_id=$1 AND company_id=$2 FOR UPDATE`, [input.candidateId, input.companyId])).rows[0];
      if ((before?.revision ?? 0) !== input.expectedRevision) fail("Inventory routing changed; export current state before approval.");
      if (!input.enabled && !before) fail("No inventory route exists to disable.");
      let provider = before?.provider, sourceScope = before?.source_scope, candidateHash = before?.candidate_hash;
      if (input.enabled) {
        const preview = await collect(); validatePreview(preview);
        const row = (await client.query(`SELECT b.*,d.candidate_hash AS imported_hash,d.source_present FROM public.customer_connector_bindings b
          JOIN public.customer_connector_drafts d ON d.id=b.candidate_id WHERE b.candidate_id=$1 AND b.company_id=$2 FOR SHARE OF b,d`,
          [input.candidateId, input.companyId])).rows[0];
        if (!row || row.revision !== input.bindingRevision) fail("Inventory binding changed; review current state before approval.");
        const scope = inventoryBindingScope(input.companyId, preview, row);
        provider = scope.provider; sourceScope = scope.sourceScope; candidateHash = row.candidate_hash;
      }
      const after = (await client.query(`INSERT INTO public.customer_inventory_routes
        (candidate_id,company_id,provider,source_scope,binding_revision,candidate_hash,revision,enabled)
        VALUES($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(candidate_id,company_id) DO UPDATE SET
        provider=EXCLUDED.provider,source_scope=EXCLUDED.source_scope,binding_revision=EXCLUDED.binding_revision,candidate_hash=EXCLUDED.candidate_hash,
        revision=customer_inventory_routes.revision+1,enabled=EXCLUDED.enabled,updated_at=now() RETURNING *`,
        [input.candidateId, input.companyId, provider, sourceScope, input.enabled ? input.bindingRevision : before!.binding_revision, candidateHash, input.enabled])).rows[0];
      await client.query(`INSERT INTO public.customer_inventory_route_audit(candidate_id,company_id,revision,actor,before_state,after_state,note)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [input.candidateId, input.companyId, after.revision, actor, before ?? null, after, input.note]);
      await client.query("COMMIT");
      return { revision: after.revision, enabled: after.enabled, provider: after.provider };
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function read(provider: RoutedInventoryProvider, collect: () => Promise<Preview>): Promise<InventoryRoute[]> {
    if (!providers.includes(provider)) fail("Unsupported inventory route provider.");
    const preview = await collect(); validatePreview(preview);
    const client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      const rows: InventoryRouteEvidence[] = (await client.query(`${inventoryRouteEvidenceSelect} WHERE r.provider=$1 AND r.enabled ORDER BY r.company_id LIMIT 1001`, [provider])).rows;
      if (rows.length > 1000) fail("Inventory routing limit exceeded.");
      const routes = rows.map(row => validateRoute(row, preview));
      if (new Set(routes.map(r => r.sourceScope)).size !== routes.length) fail("Inventory source has conflicting customer routes.");
      if (provider === "crowdstrike" && new Set(routes.map(r => r.connectionRef)).size !== routes.length) fail("CrowdStrike connection has conflicting customer routes.");
      await client.query("COMMIT"); return routes;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function exportCustomer(companyId: string) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId)) fail("Choose an existing customer.");
    const client = await db.connect();
    try {
      const rows = (await client.query(`SELECT candidate_id,company_id,binding_revision,revision,enabled,provider
        FROM public.customer_inventory_routes WHERE company_id=$1 ORDER BY candidate_id LIMIT 1001`, [companyId])).rows;
      if (rows.length > 1000) fail("Inventory routing limit exceeded.");
      return { companyId, routes: rows.map(r => ({ provider: r.provider, candidateId: r.candidate_id, companyId: r.company_id,
        bindingRevision: r.binding_revision, expectedRevision: r.revision, enabled: r.enabled })) };
    } finally { client.release(); }
  }
  return { save, read, exportCustomer };
}
