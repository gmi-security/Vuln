import type { Pool } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { validatePreview } from "./customer-connector-drafts";

type Preview = ReturnType<typeof buildConnectorPreview>;
export type OperationalRouteInput = { candidateId: string; companyId: string; bindingRevision: number; expectedRevision: number; enabled: boolean; note: string };
type OperationalRouteRow = { candidate_id: string; company_id: string; provider: string; source_scope: string;
  binding_revision: number; candidate_hash: string; revision: number; enabled: boolean };
const fail = (message: string): never => { throw new Error(message); };
function operationalTablePrefix(kind: string) {
  if (!["inventory", "spotlight", "scanner", "query"].includes(kind)) return fail("Unsupported operational route type.");
  return `customer_${kind}`;
}
export function operationalRouteEvidenceSelect(kind: "inventory" | "spotlight" | "scanner" | "query") {
  return `SELECT r.*,b.candidate_hash AS binding_hash,b.revision AS current_binding_revision,
    b.proposal,b.review_state,b.reviewed_at,d.candidate_hash AS imported_hash,d.source_present
    FROM public.${operationalTablePrefix(kind)}_routes r
    LEFT JOIN public.customer_connector_bindings b ON b.candidate_id=r.candidate_id AND b.company_id=r.company_id
    LEFT JOIN public.customer_connector_drafts d ON d.id=r.candidate_id`;
}
// Shared optimistic approval, audit and read transaction. Provider policy owns scope validation.
export function createOperationalRoutingStore<P extends string, R>(db: Pick<Pool, "connect">, policy: {
  kind: "inventory" | "spotlight" | "scanner" | "query"; providers: readonly P[];
  bindingScope: (companyId: string, preview: Preview, row: any) => { provider: P; sourceScope: string };
  validateRoute: (row: any, preview: Preview) => R;
  checkRoutes: (routes: R[], provider: P) => void;
  validatePeersOnSave?: boolean;
}) {
  const label = policy.kind[0].toUpperCase() + policy.kind.slice(1);
  const prefix = operationalTablePrefix(policy.kind);
  async function save(input: OperationalRouteInput, actor: string, collect: () => Promise<Preview>) {
    const keys = ["candidateId", "companyId", "bindingRevision", "expectedRevision", "enabled", "note"];
    if (!input || Object.keys(input).length !== keys.length || Object.keys(input).some(k => !keys.includes(k)) ||
        !/^[a-f0-9]{64}$/.test(input.candidateId) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(input.companyId) ||
        !Number.isSafeInteger(input.bindingRevision) || input.bindingRevision < 1 || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0 ||
        typeof input.enabled !== "boolean" || typeof input.note !== "string" || !input.note.trim() || input.note.length > 1000 || /[\x00-\x1f\x7f]/.test(input.note) ||
        typeof actor !== "string" || !actor || actor.length > 160 || /[\x00-\x1f\x7f]/.test(actor))
      return fail(`Invalid ${policy.kind} routing approval.`);
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SELECT pg_advisory_xact_lock(716301,1)");
      const before: OperationalRouteRow | undefined = (await client.query(`SELECT * FROM public.${prefix}_routes
        WHERE candidate_id=$1 AND company_id=$2 FOR UPDATE`, [input.candidateId, input.companyId])).rows[0];
      if ((before?.revision ?? 0) !== input.expectedRevision) fail(`${label} routing changed; export current state before approval.`);
      if (!input.enabled && !before) fail(`No ${policy.kind} route exists to disable.`);
      let provider = before?.provider, sourceScope = before?.source_scope, candidateHash = before?.candidate_hash;
      let preview: Preview | undefined;
      if (input.enabled) {
        preview = await collect(); validatePreview(preview);
        const row = (await client.query(`SELECT b.*,d.candidate_hash AS imported_hash,d.source_present FROM public.customer_connector_bindings b
          JOIN public.customer_connector_drafts d ON d.id=b.candidate_id WHERE b.candidate_id=$1 AND b.company_id=$2 FOR SHARE OF b,d`,
          [input.candidateId, input.companyId])).rows[0];
        if (!row || row.revision !== input.bindingRevision) fail(`${label} binding changed; review current state before approval.`);
        const scope = policy.bindingScope(input.companyId, preview, row);
        provider = scope.provider; sourceScope = scope.sourceScope; candidateHash = row.candidate_hash;
      }
      const after = (await client.query(`INSERT INTO public.${prefix}_routes
        (candidate_id,company_id,provider,source_scope,binding_revision,candidate_hash,revision,enabled)
        VALUES($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(candidate_id,company_id) DO UPDATE SET
        provider=EXCLUDED.provider,source_scope=EXCLUDED.source_scope,binding_revision=EXCLUDED.binding_revision,candidate_hash=EXCLUDED.candidate_hash,
        revision=${prefix}_routes.revision+1,enabled=EXCLUDED.enabled,updated_at=now() RETURNING *`,
        [input.candidateId, input.companyId, provider, sourceScope, input.enabled ? input.bindingRevision : before!.binding_revision, candidateHash, input.enabled])).rows[0];
      if (input.enabled && policy.validatePeersOnSave) {
        const peers = (await client.query(`${operationalRouteEvidenceSelect(policy.kind)} WHERE r.provider=$1 AND r.enabled LIMIT 1001`, [provider])).rows;
        if (peers.length > 1000) fail(`${label} routing limit exceeded.`);
        policy.checkRoutes(peers.map(row => policy.validateRoute(row, preview!)), provider as P);
      }
      await client.query(`INSERT INTO public.${prefix}_route_audit(candidate_id,company_id,revision,actor,before_state,after_state,note)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [input.candidateId, input.companyId, after.revision, actor, before ?? null, after, input.note]);
      await client.query("COMMIT");
      return { revision: after.revision, enabled: after.enabled, provider: after.provider };
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function read(provider: P, collect: () => Promise<Preview>): Promise<R[]> {
    if (!policy.providers.includes(provider)) fail(`Unsupported ${policy.kind} route provider.`);
    const preview = await collect(); validatePreview(preview);
    const client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      const rows: any[] = (await client.query(`${operationalRouteEvidenceSelect(policy.kind)} WHERE r.provider=$1 AND r.enabled ORDER BY r.company_id LIMIT 1001`, [provider])).rows;
      if (rows.length > 1000) fail(`${label} routing limit exceeded.`);
      const routes = rows.map(row => policy.validateRoute(row, preview));
      policy.checkRoutes(routes, provider);
      await client.query("COMMIT"); return routes;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  async function exportCustomer(companyId: string) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId)) fail("Choose an existing customer.");
    const client = await db.connect();
    try {
      const rows = (await client.query(`SELECT candidate_id,company_id,binding_revision,revision,enabled,provider
        FROM public.${prefix}_routes WHERE company_id=$1 ORDER BY candidate_id LIMIT 1001`, [companyId])).rows;
      if (rows.length > 1000) fail(`${label} routing limit exceeded.`);
      return { companyId, routes: rows.map(r => ({ provider: r.provider, candidateId: r.candidate_id, companyId: r.company_id,
        bindingRevision: r.binding_revision, expectedRevision: r.revision, enabled: r.enabled })) };
    } finally { client.release(); }
  }
  return { save, read, exportCustomer };
}
