import { elasticDatasets } from "./customer-elastic-scope";
import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { buildConnectorPreview } from "./customer-connector-preview";
import { checkCustomerConnectorBinding, type CustomerBindingEvidence } from "./customer-connector-routing";
import { planCustomerSourceAuthority, sourceSelectionHash, type AuthorityEvidence } from "./customer-source-authority";

type Preview = ReturnType<typeof buildConnectorPreview>;
export type SelectionBinding = CustomerBindingEvidence & { revision: number; provider: string };
export type MirrorSelection = { candidateId: string; primaryId: string; evidenceRef: string };
type Review = { companyId: string; expectedRevision: number; decision: "reviewed" | "revoked";
  bindingsFingerprint: string | null; mirrors: MirrorSelection[]; note: string };
type SavedSelection = { company_id: string; revision: number; state: string; bindings_fingerprint: string | null;
  mirrors: MirrorSelection[]; sources: AuthorityEvidence[]; reviewed_at: Date | string; reviewed_by: string };
// jsonb does not retain object key order. Review fingerprints must survive a
// database round trip while retaining meaningful array and field changes.
const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ?
  Object.fromEntries(Object.entries(value).sort(([a],[b]) => a.localeCompare(b)).map(([key,item]) => [key,canonical(item)])) : value;
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
const fail = (message: string): never => { throw new Error(message); };
const companyKey = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(value);
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const text = (value: unknown, max: number): value is string => typeof value === "string" && Boolean(value.trim()) && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => Boolean(value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key)));

export function sourceSelectionReview(value: unknown): Review {
  if (!exact(value,["companyId","expectedRevision","decision","bindingsFingerprint","mirrors","note"]) ||
      !companyKey(value.companyId) || !Number.isSafeInteger(value.expectedRevision) || Number(value.expectedRevision) < 0 || Number(value.expectedRevision) >= 2147483647 ||
      !["reviewed","revoked"].includes(String(value.decision)) || !text(value.note,500) || !Array.isArray(value.mirrors) || value.mirrors.length > 100 ||
      (value.decision === "reviewed" ? !digest(value.bindingsFingerprint) : value.bindingsFingerprint !== null || value.mirrors.length !== 0))
    return fail("Invalid customer source selection review.");
  for (const mirror of value.mirrors) if (!exact(mirror,["candidateId","primaryId","evidenceRef"]) ||
    !digest(mirror.candidateId) || !digest(mirror.primaryId) || !text(mirror.evidenceRef,256)) return fail("Invalid mirror evidence reference.");
  if (new Set(value.mirrors.map(m => m.candidateId)).size !== value.mirrors.length) return fail("Duplicate mirror selection.");
  return { ...value, mirrors: [...value.mirrors].sort((a,b) => a.candidateId.localeCompare(b.candidateId)) } as Review;
}

/** Covers the complete non-dismissed binding set, including changed roles and
 * newly added assignments. Review cannot silently omit an unreviewed source.
 */
export function sourceSelectionEvidence(companyId: string, preview: Preview, rows: SelectionBinding[]) {
  if (!companyKey(companyId) || !preview.companies.some(c => c.id === companyId)) return fail("Choose an existing customer.");
  if (rows.length > 1000 || new Set(rows.map(r => r.id)).size !== rows.length || rows.some(r => r.proposal?.companyId !== companyId))
    return fail("Invalid customer source binding set.");
  const own = rows.filter(r => r.reviewState !== "dismissed").sort((a,b) => a.id.localeCompare(b.id));
  const fingerprint = hash(own.map(row => [row.id,row.revision,row.candidateHash,row.importedHash,row.sourcePresent,row.reviewState,row.proposal]));
  const bindings = own.map(row => ({ row, checked: checkCustomerConnectorBinding(companyId,preview,row) }));
  const blocked = bindings.filter(b => !b.checked.ready);
  const endpoints = bindings.flatMap(({row,checked}) => checked.ready && (
    checked.binding.domains.includes("endpoint-findings") || checked.binding.scope.authority === "mirror"
  ) ? [{ row, binding: checked.binding }] : []);
  return { fingerprint, bindings, blocked, endpoints };
}

export function buildReviewedSourceSelection(companyId: string, preview: Preview, rows: SelectionBinding[], mirrors: MirrorSelection[]) {
  const evidence = sourceSelectionEvidence(companyId,preview,rows);
  if (evidence.blocked.length) return fail("Review all current customer bindings before selecting primary sources and mirrors.");
  const mirrorBindings = evidence.endpoints.filter(b => b.binding.scope.authority === "mirror");
  const primaries = evidence.endpoints.filter(b => b.binding.scope.authority === "findings-primary");
  // An Elastic query binding can describe a mirrored dataset without changing
  // its query-only role and invalidating the existing saved-query approval.
  const queryMirrors = evidence.bindings.flatMap(({row,checked}) => checked.ready && checked.binding.candidate.provider === "elastic" &&
    checked.binding.scope.authority === "query-only" ? [{row,binding:checked.binding}] : []);
  if (mirrorBindings.some(b => !mirrors.some(m => m.candidateId === b.row.id)) || new Set(mirrors.map(m => m.candidateId)).size !== mirrors.length)
    return fail("Every mirror requires exactly one reviewed primary and evidence reference.");
  for (const link of mirrors) {
    const mirror = [...mirrorBindings,...queryMirrors].find(b => b.row.id === link.candidateId), primary = primaries.find(b => b.row.id === link.primaryId);
    // This first persisted mirror contract covers Elastic copies of endpoint
    // datasets. Other mirroring/lifecycle semantics need their own adapter.
    if (!mirror || !primary || mirror.binding.candidate.provider !== "elastic" ||
        !["defender","crowdstrike"].includes(primary.binding.candidate.provider) ||
        !mirror.binding.scope.datasets.length || !text(link.evidenceRef,256) || !primary.binding.scope.tenantId)
      return fail("Mirror target must be a reviewed endpoint primary for the same customer with explicit mapping evidence.");
    elasticDatasets(mirror.binding.scope.datasets);
  }
  const origin = (item: typeof primaries[number]) => hash([item.binding.candidate.provider,
    ["defender","crowdstrike"].includes(item.binding.candidate.provider) ? item.binding.scope.tenantId?.toLowerCase() : item.binding.scope.tenantId,
    // Vendor tenant identifies one origin even when configured more than once.
    item.binding.scope.tenantId ? null : item.binding.candidate.connectionRef,item.binding.scope.datasets,item.binding.scope.targets]);
  if (new Set(primaries.map(origin)).size !== primaries.length) return fail("Duplicate primary source origin; reconcile assignments first.");
  const selected = [...evidence.endpoints,...queryMirrors.filter(b => mirrors.some(m => m.candidateId === b.row.id))];
  const entries: AuthorityEvidence[] = selected.map(item => {
    const mirror = mirrors.find(m => m.candidateId === item.row.id), primary = mirror ? primaries.find(p => p.row.id === mirror.primaryId)! : item;
    const provider = item.binding.candidate.provider;
    const fullScope = !item.binding.scope.datasets.length && !item.binding.scope.targets.length;
    const reader = fullScope && provider === "defender" && item.binding.candidate.evidence === "saved-binding" &&
      item.binding.candidate.connectionRef === `application:defender_connections:${companyId}` ? "defender-saved-v1" :
      fullScope && provider === "crowdstrike" && item.binding.candidate.evidence === "environment-match" &&
      item.binding.candidate.capabilities.includes("vulnerability-import") && /^[a-f0-9]{32}$/i.test(item.binding.scope.tenantId ?? "") ? "spotlight-summary-v1" : null;
    const entry: AuthorityEvidence = { id:item.row.id, companyId, provider, domain:"endpoint-findings", authority:mirror ? "mirror" : item.binding.scope.authority,
      originKey:origin(primary), mirrorOf:mirror?.primaryId ?? null, configured:true, sourcePresent:true, scopeVerified:true,
      sourceFingerprint:hash([item.row.revision,item.row.candidateHash,item.binding.scope]), reviewedSelectionHash:null,
      reader:mirror ? null : reader };
    entry.reviewedSelectionHash = sourceSelectionHash(entry); return entry;
  });
  return { fingerprint:evidence.fingerprint, plan:planCustomerSourceAuthority(companyId,entries), entries };
}

export const sourceSelectionBindingsSql = `SELECT b.candidate_id AS id,b.company_id,b.revision,b.candidate_hash AS "candidateHash",
  d.candidate_hash AS "importedHash",d.source_present AS "sourcePresent",b.review_state AS "reviewState",b.reviewed_at AS "reviewedAt",
  b.proposal,d.candidate->>'provider' AS provider FROM customer_connector_bindings b
  JOIN customer_connector_drafts d ON d.id=b.candidate_id WHERE b.company_id=$1 ORDER BY b.candidate_id LIMIT 1001`;
export type SourceSelectionStatus = { state:"not-installed"|"unreviewed"|"revoked"|"needs-review"|"reviewed"; revision:number;
  primaryCount:number; mirrorCount:number; readiness:string; canActivate:false };
export function sourceSelectionStatus(companyId: string, preview: Preview, bindings: SelectionBinding[], saved?: SavedSelection): SourceSelectionStatus {
  const base = { revision:saved?.revision ?? 0, primaryCount:0, mirrorCount:0, readiness:"Source selection has not been reviewed.", canActivate:false as const };
  if (!saved) return {...base,state:"unreviewed"};
  if (saved.company_id !== companyId) return fail("Source selection belongs to a different customer.");
  if (saved.state === "revoked") return {...base,state:"revoked",readiness:"Source selection review was revoked. Existing operational routing is unchanged."};
  try {
    const current = buildReviewedSourceSelection(companyId,preview,bindings,saved.mirrors);
    if (saved.state !== "reviewed" || !saved.reviewed_at || current.fingerprint !== saved.bindings_fingerprint || hash(current.entries) !== hash(saved.sources)) throw Error();
    const p = current.plan;
    return {...base,state:"reviewed",primaryCount:p.proposedSources.length,mirrorCount:p.excludedMirrors.length,
      readiness:p.state === "ready-for-comparison" ? "One primary source is selected for comparison. Reporting has not switched." :
        p.state === "no-findings-source" ? "No endpoint findings source is selected. Other connector roles are retained." :
        p.state === "requires-record-correlation" ? "Multiple primary sources require finding-level correlation before combined reporting." :
        "Source selection is recorded; a compatible saved reader is still required before reporting can switch."};
  } catch { return {...base,state:"needs-review",readiness:"Bindings or source configuration changed. Review source selection again."}; }
}

export async function readSourceSelectionStatus(client: Pick<PoolClient,"query">, companyId: string, preview: Preview): Promise<SourceSelectionStatus> {
  const installed = (await client.query("SELECT to_regclass('public.customer_source_selections') AS selection")).rows[0]?.selection;
  if (!installed) return {state:"not-installed",revision:0,primaryCount:0,mirrorCount:0,readiness:"Source selection review is not installed. Existing reporting is unchanged.",canActivate:false};
  const rows = (await client.query(sourceSelectionBindingsSql,[companyId])).rows as SelectionBinding[];
  const saved = (await client.query("SELECT * FROM customer_source_selections WHERE company_id=$1",[companyId])).rows[0];
  return sourceSelectionStatus(companyId,preview,rows,saved);
}

/** Operator-only, audited review. No live routes, source data or writers change. */
export function createSourceSelectionStore(db: Pick<Pool,"connect">) {
  async function save(value: unknown, actor: string, collect: () => Promise<Preview>) {
    const input = sourceSelectionReview(value);
    if (!text(actor,160)) return fail("An operator identity is required.");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='30s'");
      await client.query("SELECT pg_advisory_xact_lock(716301,1)");
      const prior = (await client.query("SELECT * FROM customer_source_selections WHERE company_id=$1 FOR UPDATE",[input.companyId])).rows[0];
      if ((prior?.revision ?? 0) !== input.expectedRevision) return fail("Source selection changed; export current state before review.");
      let sources: AuthorityEvidence[] = [];
      if (input.decision === "reviewed") {
        const preview = await collect(), rows = (await client.query(sourceSelectionBindingsSql,[input.companyId])).rows as SelectionBinding[];
        const current = buildReviewedSourceSelection(input.companyId,preview,rows,input.mirrors);
        sources = current.entries;
        if (input.bindingsFingerprint !== current.fingerprint) return fail("Customer bindings changed; export current state before review.");
      } else if (!prior) return fail("No source selection exists to revoke.");
      const next = (await client.query(`INSERT INTO customer_source_selections(company_id,revision,state,bindings_fingerprint,mirrors,reviewed_by,reviewed_at,sources)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,now(),$7::jsonb) ON CONFLICT(company_id) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,
        bindings_fingerprint=EXCLUDED.bindings_fingerprint,mirrors=EXCLUDED.mirrors,sources=EXCLUDED.sources,reviewed_by=EXCLUDED.reviewed_by,reviewed_at=EXCLUDED.reviewed_at
        RETURNING *`,[input.companyId,input.expectedRevision+1,input.decision,input.bindingsFingerprint,JSON.stringify(input.mirrors),actor,JSON.stringify(sources)])).rows[0];
      await client.query(`INSERT INTO customer_source_selection_audit(company_id,revision,actor,action,before_state,after_state,note)
        VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)`,[input.companyId,next.revision,actor,input.decision,JSON.stringify(prior ?? null),JSON.stringify(next),input.note]);
      await client.query("COMMIT"); return {revision:next.revision,state:next.state,canActivate:false};
    } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; } finally { client.release(); }
  }
  async function exportCustomer(companyId: string, collect: () => Promise<Preview>) {
    if (!companyKey(companyId)) return fail("Choose an existing customer.");
    const preview = await collect(), client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      const rows = (await client.query(sourceSelectionBindingsSql,[companyId])).rows as SelectionBinding[];
      const saved = (await client.query("SELECT * FROM customer_source_selections WHERE company_id=$1",[companyId])).rows[0];
      const evidence = sourceSelectionEvidence(companyId,preview,rows);
      await client.query("COMMIT");
      return {companyId,status:sourceSelectionStatus(companyId,preview,rows,saved),
        bindings:evidence.bindings.map(({row,checked})=>({candidateId:row.id,provider:row.provider,authority:row.proposal.authority,reviewed:checked.ready})),
        reviewRequest:{companyId,expectedRevision:saved?.revision ?? 0,decision:"reviewed",bindingsFingerprint:evidence.fingerprint,
          mirrors:saved?.state === "reviewed" ? saved.mirrors : [],note:""},canActivate:false};
    } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; } finally { client.release(); }
  }
  return {save,exportCustomer};
}
