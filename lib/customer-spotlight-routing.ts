import { createHash } from "node:crypto";
import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { validatePreview, type ConnectorProposal } from "./customer-connector-drafts";
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
export const spotlightRouteEvidenceSelect = `SELECT r.*,b.candidate_hash AS binding_hash,b.revision AS current_binding_revision,
  b.proposal,b.review_state,b.reviewed_at,d.candidate_hash AS imported_hash,d.source_present
  FROM public.customer_spotlight_routes r
  LEFT JOIN public.customer_connector_bindings b ON b.candidate_id=r.candidate_id AND b.company_id=r.company_id
  LEFT JOIN public.customer_connector_drafts d ON d.id=r.candidate_id`;
export type SpotlightRoutingStatus = { id: string; review: string; routing: string };
// Only these fixed labels reach the browser; private scope and audit fields do not.
export function spotlightRoutingStatus(row: SpotlightRouteEvidence, preview: Preview, rawProviders?: string): SpotlightRoutingStatus {
  const id = row.candidate_id;
  if (!row.enabled) return { id, review: "Spotlight route disabled", routing: "This operational approval is disabled. Legacy routing may still apply if the provider switch is off." };
  try {
    const route = validateRoute(row, preview);
    if (!reviewedSpotlightProviders(rawProviders).includes(route.provider))
      return { id, review: "Spotlight route approved", routing: "Approval recorded; the provider routing switch is off. Existing import routing still applies." };
    return { id, review: "Spotlight route approved", routing: "Approved for spotlight routing; the provider switch is on. All routes are checked again when an import starts. This does not confirm a successful import." };
  } catch { return { id, review: "Spotlight routing needs review", routing: "This approval or provider configuration is stale or invalid. An opted-in import stops until it is resolved." }; }
}
export type SpotlightRouteInput = {
  candidateId: string; companyId: string; bindingRevision: number; expectedRevision: number; enabled: boolean; note: string;
};
/** Separate operational approval; reviewing a binding alone never starts routing.
 * No schema initialization, credentials, upstream calls or platform writes.
 */
export function createSpotlightRoutingStore(db: Pick<Pool, "connect">) {
  async function save(input: SpotlightRouteInput, actor: string, collect: () => Promise<Preview>) {
    const keys = ["candidateId", "companyId", "bindingRevision", "expectedRevision", "enabled", "note"];
    if (!input || Object.keys(input).length !== keys.length || Object.keys(input).some(k => !keys.includes(k)) ||
        !/^[a-f0-9]{64}$/.test(input.candidateId) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(input.companyId) ||
        !Number.isSafeInteger(input.bindingRevision) || input.bindingRevision < 1 || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0 ||
        typeof input.enabled !== "boolean" || typeof input.note !== "string" || !input.note.trim() || input.note.length > 1000 || /[\x00-\x1f\x7f]/.test(input.note) ||
        typeof actor !== "string" || !actor || actor.length > 160 || /[\x00-\x1f\x7f]/.test(actor))
      return fail("Invalid spotlight routing approval.");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SELECT pg_advisory_xact_lock(716301,1)");
      const before: RouteRow | undefined = (await client.query(`SELECT * FROM public.customer_spotlight_routes
        WHERE candidate_id=$1 AND company_id=$2 FOR UPDATE`, [input.candidateId, input.companyId])).rows[0];
      if ((before?.revision ?? 0) !== input.expectedRevision) fail("Spotlight routing changed; export current state before approval.");
      if (!input.enabled && !before) fail("No spotlight route exists to disable.");
      let provider = before?.provider, sourceScope = before?.source_scope, candidateHash = before?.candidate_hash;
      if (input.enabled) {
        const preview = await collect(); validatePreview(preview);
        const row = (await client.query(`SELECT b.*,d.candidate_hash AS imported_hash,d.source_present FROM public.customer_connector_bindings b
          JOIN public.customer_connector_drafts d ON d.id=b.candidate_id WHERE b.candidate_id=$1 AND b.company_id=$2 FOR SHARE OF b,d`,
          [input.candidateId, input.companyId])).rows[0];
        if (!row || row.revision !== input.bindingRevision) fail("Spotlight binding changed; review current state before approval.");
        const scope = spotlightBindingScope(input.companyId, preview, row);
        provider = scope.provider; sourceScope = scope.sourceScope; candidateHash = row.candidate_hash;
      }
      const after = (await client.query(`INSERT INTO public.customer_spotlight_routes
        (candidate_id,company_id,provider,source_scope,binding_revision,candidate_hash,revision,enabled)
        VALUES($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(candidate_id,company_id) DO UPDATE SET
        provider=EXCLUDED.provider,source_scope=EXCLUDED.source_scope,binding_revision=EXCLUDED.binding_revision,candidate_hash=EXCLUDED.candidate_hash,
        revision=customer_spotlight_routes.revision+1,enabled=EXCLUDED.enabled,updated_at=now() RETURNING *`,
        [input.candidateId, input.companyId, provider, sourceScope, input.enabled ? input.bindingRevision : before!.binding_revision, candidateHash, input.enabled])).rows[0];
      await client.query(`INSERT INTO public.customer_spotlight_route_audit(candidate_id,company_id,revision,actor,before_state,after_state,note)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [input.candidateId, input.companyId, after.revision, actor, before ?? null, after, input.note]);
      await client.query("COMMIT");
      return { revision: after.revision, enabled: after.enabled, provider: after.provider };
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function read(provider: RoutedSpotlightProvider, collect: () => Promise<Preview>): Promise<SpotlightRoute[]> {
    if (!providers.includes(provider)) fail("Unsupported spotlight route provider.");
    const preview = await collect(); validatePreview(preview);
    const client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      const rows: SpotlightRouteEvidence[] = (await client.query(`${spotlightRouteEvidenceSelect} WHERE r.provider=$1 AND r.enabled ORDER BY r.company_id LIMIT 1001`, [provider])).rows;
      if (rows.length > 1000) fail("Spotlight routing limit exceeded.");
      const routes = rows.map(row => validateRoute(row, preview));
      if (new Set(routes.map(r => r.sourceScope)).size !== routes.length) fail("Spotlight source has conflicting customer routes.");
      if (provider === "crowdstrike" && new Set(routes.map(r => r.connectionRef)).size !== routes.length) fail("CrowdStrike connection has conflicting customer routes.");
      if (new Set(routes.map(r => r.companyId)).size !== routes.length) fail("Spotlight customer has conflicting routes.");
      await client.query("COMMIT"); return routes;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function exportCustomer(companyId: string) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId)) fail("Choose an existing customer.");
    const client = await db.connect();
    try {
      const rows = (await client.query(`SELECT candidate_id,company_id,binding_revision,revision,enabled,provider
        FROM public.customer_spotlight_routes WHERE company_id=$1 ORDER BY candidate_id LIMIT 1001`, [companyId])).rows;
      if (rows.length > 1000) fail("Spotlight routing limit exceeded.");
      return { companyId, routes: rows.map(r => ({ provider: r.provider, candidateId: r.candidate_id, companyId: r.company_id,
        bindingRevision: r.binding_revision, expectedRevision: r.revision, enabled: r.enabled })) };
    } finally { client.release(); }
  }
  return { save, read, exportCustomer };
}
