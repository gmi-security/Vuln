import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { ConnectorCandidate, buildConnectorPreview } from "./customer-connector-preview";

type Preview = ReturnType<typeof buildConnectorPreview>;
export type ConnectorProposal = {
  companyId: string | null;
  tenantId: string | null;
  datasets: string[];
  targets: string[];
  authority: "unassigned" | "findings-primary" | "inventory" | "enrichment" | "query-only" | "mirror";
};
type Draft = {
  id: string; candidate: ConnectorCandidate; candidate_hash: string; proposal: ConnectorProposal;
  source_evidence: ConnectorCandidate[];
  source_present: boolean; review_state: "pending-review" | "reviewed" | "dismissed" | "needs-review";
  revision: number; enabled: false; reviewed_by: string | null; reviewed_at: Date | string | null;
};
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export function connectorDraftEvidence(candidate: ConnectorCandidate, candidates: ConnectorCandidate[]) {
  const sourceEvidence = candidate.evidence === "saved-tile" ? candidates.filter(c =>
    c.evidence === "shared-configuration" && c.connectionRef === candidate.connectionRef && c.provider === candidate.provider) : [];
  return { sourceEvidence, candidateHash: hash({ candidate, sourceEvidence }) };
}
const digestPattern = /^[a-f0-9]{64}$/;
const assert = (condition: unknown, message: string): void => { if (!condition) throw new Error(message); };
function short(value: unknown, max = 256): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
}
function exactKeys(value: object, keys: string[]) {
  assert(Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key)), "Unexpected registry fields.");
}
export function validatePreview(preview: Preview) {
  assert(preview && typeof preview === "object", "Invalid connector preview.");
  exactKeys(preview, ["version", "mode", "companies", "candidates", "limitations", "fingerprint"]);
  assert(preview.version === 1 && preview.mode === "preview-only", "Unsupported connector preview.");
  const { fingerprint, ...body } = preview;
  assert(digestPattern.test(fingerprint) && hash(body) === fingerprint, "Preview integrity check failed.");
  assert(Array.isArray(preview.candidates) && preview.candidates.length <= 10000 &&
    Buffer.byteLength(JSON.stringify(preview)) <= 10 * 1024 * 1024, "Connector preview exceeds import limits.");
  const ids = new Set<string>();
  for (const c of preview.candidates) {
    exactKeys(c, ["id", "provider", "connectionRef", "companyId", "evidence", "capabilities", "tenantId", "scope", "revision", "tileId", "runId", "configured", "review", "state", "enabled", "authority"]);
    assert(digestPattern.test(c.id) && !ids.has(c.id) && c.id === hash([c.provider, c.connectionRef, c.evidence, c.tileId,
      c.evidence === "completed-import" ? c.companyId : c.runId]), "Invalid or duplicate candidate identity.");
    ids.add(c.id);
    assert(short(c.provider, 64) && /^[a-z][a-z0-9-]*$/.test(c.provider), "Invalid provider.");
    for (const field of [c.connectionRef, c.companyId, c.tenantId, c.tileId, c.runId]) assert(field === null || short(field), "Invalid candidate reference.");
    assert(c.connectionRef === null || /^(application:|dashboard:|environment:)/.test(c.connectionRef), "Unknown credential reference kind.");
    assert(["saved-binding", "environment-match", "shared-configuration", "saved-tile", "completed-import"].includes(c.evidence), "Invalid candidate evidence.");
    assert(["tenant", "unverified", "historical-only"].includes(c.scope), "Invalid candidate scope.");
    assert(Array.isArray(c.capabilities) && c.capabilities.length <= 8 && c.capabilities.every(v =>
      ["vulnerability-import", "inventory", "scan", "enrichment", "saved-query", "appsec", "ticket-delivery", "orchestration"].includes(v)), "Invalid capabilities.");
    assert(Array.isArray(c.review) && c.review.length <= 30 && c.review.every(v => short(v, 100) && /^[a-z-]+$/.test(v)), "Invalid review reasons.");
    assert(c.revision === null || Number.isSafeInteger(c.revision) && c.revision > 0, "Invalid source revision.");
    assert(typeof c.configured === "boolean" && c.state === "pending-review" && c.enabled === false && c.authority === "unassigned", "Import candidates must be disabled and unreviewed.");
  }
}
export function proposal(value: ConnectorProposal): ConnectorProposal {
  assert(value && typeof value === "object", "Invalid connector proposal.");
  exactKeys(value, ["companyId", "tenantId", "datasets", "targets", "authority"]);
  assert(value.companyId === null || short(value.companyId, 100), "Invalid proposal customer.");
  assert(value.tenantId === null || short(value.tenantId), "Invalid proposal tenant.");
  for (const values of [value.datasets, value.targets]) assert(Array.isArray(values) && values.length <= 100 &&
    values.every(v => short(v)), "Invalid dataset or target list.");
  assert(["unassigned", "findings-primary", "inventory", "enrichment", "query-only", "mirror"].includes(value.authority), "Invalid proposed authority.");
  return { companyId: value.companyId, tenantId: value.tenantId,
    datasets: [...new Set(value.datasets)].sort(), targets: [...new Set(value.targets)].sort(), authority: value.authority };
}
export function validateReviewScope(candidate: ConnectorCandidate, sourcePresent: boolean, sourceEvidence: ConnectorCandidate[], next: ConnectorProposal) {
  assert(sourcePresent && candidate.configured && candidate.connectionRef !== null &&
    candidate.evidence !== "completed-import", "Only present configured connections can be reviewed as bindings.");
  assert(next.companyId && (!candidate.companyId || candidate.companyId === next.companyId), "Resolve existing customer ownership before review.");
  assert(!candidate.review.some(code => ["saved-environment-tenant-conflict", "vendor-tenant-has-multiple-customers",
    "legacy-loader-stops-before-this-entry", "legacy-loader-ignores-without-tenant", "adapter-planned", "unrecognized-cloud"].includes(code)),
  "Resolve source configuration conflicts before review.");
  if (candidate.tenantId) assert(next.tenantId === candidate.tenantId, "Resolve the saved tenant mapping before review.");
  if (candidate.evidence === "saved-tile") assert(sourceEvidence.length > 0 && sourceEvidence.every(c => c.configured), "Saved query connection evidence is missing.");
  const allowed = candidate.capabilities.flatMap(capability => ({
    "vulnerability-import": ["findings-primary", "mirror"], "scan": ["findings-primary"],
    "inventory": ["inventory"], "enrichment": ["enrichment"], "saved-query": ["query-only", "mirror"],
    "appsec": ["query-only"], "ticket-delivery": [], "orchestration": [],
  }[capability]));
  assert(allowed.includes(next.authority), "Choose authority supported by this source capability.");
  if (next.authority !== "enrichment") assert(next.tenantId || next.datasets.length || next.targets.length, "Record the verified tenant, dataset or targets before review.");
  if (candidate.provider === "defender" || candidate.provider === "crowdstrike") assert(next.tenantId, "Vendor tenant verification is required.");
  if (candidate.provider === "elastic") assert(next.datasets.length > 0, "Elasticsearch dataset verification is required.");
  if (candidate.capabilities.includes("scan") && next.authority !== "enrichment") assert(next.targets.length > 0, "Approved scanner targets are required.");
  if (candidate.capabilities.includes("appsec")) assert(next.datasets.length > 0 && next.targets.length > 0, "Approved AppSec datasets and repositories are required.");
}
function snapshot(row: Draft) {
  return { candidate: row.candidate, candidateHash: row.candidate_hash, sourceEvidence: row.source_evidence, proposal: row.proposal,
    sourcePresent: row.source_present, reviewState: row.review_state, revision: row.revision,
    enabled: row.enabled, reviewedBy: row.reviewed_by, reviewedAt: row.reviewed_at };
}

// No production singleton, schema initializer, HTTP mutation route or worker.
// Operator commands use reviewCurrentDraft with a trusted metadata collector.
// Uploaded JSON is never source evidence or an authenticated actor.
export function createConnectorDraftStore(db: Pick<Pool, "connect" | "query">) {
  async function transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      // All registry mutations share this lock; unrelated application tables do not.
      await client.query("SELECT pg_advisory_xact_lock(716301, 1)");
      const result = await work(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  async function audit(client: PoolClient, actor: string, action: string, after: Draft, before: Draft | null,
    importId: string | null = null, note: string | null = null) {
    await client.query(`INSERT INTO customer_connector_audit(draft_id,import_id,action,actor,revision,before_state,after_state,note)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [after.id, importId, action, actor, after.revision,
      before ? JSON.stringify(snapshot(before)) : null, JSON.stringify(snapshot(after)), note]);
  }
  async function importPreview(expectedFingerprint: string, actor: string, collect: () => Promise<Preview>) {
    assert(short(actor, 160) && digestPattern.test(expectedFingerprint), "Actor and reviewed fingerprint are required.");
    return transaction(async client => {
      // Recollect after acquiring the registry lock. Source databases are separate
      // snapshots: activation must still recheck source revisions and tenant scope.
      const preview = await collect();
      validatePreview(preview);
      assert(preview.fingerprint === expectedFingerprint, "Source metadata changed; collect and review a new preview.");
      const previous = (await client.query("SELECT id,fingerprint FROM connector_registry_imports ORDER BY id DESC LIMIT 1")).rows[0];
      if (previous?.fingerprint === preview.fingerprint) return { importId: String(previous.id), unchanged: true, created: 0, changed: 0, missing: 0 };
      const importId = String((await client.query(`INSERT INTO connector_registry_imports(fingerprint,actor,candidate_count)
        VALUES($1,$2,$3) RETURNING id`, [preview.fingerprint, actor, preview.candidates.length])).rows[0].id);
      const current = new Map<string, Draft>((await client.query("SELECT * FROM customer_connector_drafts ORDER BY id FOR UPDATE")).rows.map(row => [row.id, row]));
      let created = 0, changed = 0, missing = 0;
      for (const candidate of preview.candidates) {
        const before = current.get(candidate.id);
        current.delete(candidate.id);
        // A saved query depends on a separately stored connection revision.
        // Credential/tenant changes there must invalidate the tile's review too.
        const { sourceEvidence, candidateHash } = connectorDraftEvidence(candidate, preview.candidates);
        if (!before) {
          const initial = proposal({ companyId: candidate.companyId, tenantId: candidate.tenantId, datasets: [], targets: [], authority: "unassigned" });
          const after = (await client.query(`INSERT INTO customer_connector_drafts(id,candidate,candidate_hash,proposal,last_seen_import,source_evidence)
            VALUES($1,$2,$3,$4,$5,$6) RETURNING *`, [candidate.id, JSON.stringify(candidate), candidateHash, JSON.stringify(initial), importId, JSON.stringify(sourceEvidence)])).rows[0];
          await audit(client, actor, "imported", after, null, importId); created++;
        } else if (before.candidate_hash !== candidateHash || !before.source_present) {
          const after = (await client.query(`UPDATE customer_connector_drafts SET candidate=$2,candidate_hash=$3,source_present=true,
            review_state='needs-review',revision=revision+1,last_seen_import=$4,source_evidence=$5,updated_at=now() WHERE id=$1 RETURNING *`,
          [candidate.id, JSON.stringify(candidate), candidateHash, importId, JSON.stringify(sourceEvidence)])).rows[0];
          // Proposal and historical reviewer fields deliberately remain intact.
          await audit(client, actor, before.source_present ? "source-changed" : "source-restored", after, before, importId); changed++;
        } else {
          await client.query("UPDATE customer_connector_drafts SET last_seen_import=$2 WHERE id=$1", [candidate.id, importId]);
        }
      }
      for (const before of current.values()) {
        if (!before.source_present) continue;
        const after = (await client.query(`UPDATE customer_connector_drafts SET source_present=false,review_state='needs-review',
          revision=revision+1,updated_at=now() WHERE id=$1 RETURNING *`, [before.id])).rows[0];
        await audit(client, actor, "source-missing", after, before, importId); missing++;
      }
      return { importId, unchanged: false, created, changed, missing };
    });
  }
  async function reviewDraft(input: { id: string; expectedRevision: number; candidateHash: string;
    decision: "save-draft" | "reviewed" | "dismissed"; proposal: ConnectorProposal; note: string },
    actor: string, resolveCompany: (id: string) => Promise<{ id: string; isDemo?: boolean }>, collect?: () => Promise<Preview>) {
    assert(input && typeof input === "object", "Invalid review request.");
    exactKeys(input, ["id", "expectedRevision", "candidateHash", "decision", "proposal", "note"]);
    assert(short(actor, 160) && digestPattern.test(input.id) && digestPattern.test(input.candidateHash) &&
      Number.isSafeInteger(input.expectedRevision) && input.expectedRevision > 0, "Valid actor and draft revision required.");
    assert(["save-draft", "reviewed", "dismissed"].includes(input.decision) && short(input.note, 1000), "Decision and review note required.");
    const next = proposal(input.proposal);
    return transaction(async client => {
      const before: Draft | undefined = (await client.query("SELECT * FROM customer_connector_drafts WHERE id=$1 FOR UPDATE", [input.id])).rows[0];
      assert(before && before.revision === input.expectedRevision && before.candidate_hash === input.candidateHash, "Draft changed; reload before reviewing.");
      const draft = before!;
      if (collect) {
        // Recollect while holding the same registry lock used by imports/reviews.
        // This detects source changes even when nobody has rerun the import tool.
        const fresh = await collect();
        validatePreview(fresh);
        const candidate = fresh.candidates.find(c => c.id === draft.id);
        assert(candidate ? draft.source_present &&
          connectorDraftEvidence(candidate, fresh.candidates).candidateHash === draft.candidate_hash : !draft.source_present,
        "Source metadata changed; import a fresh preview before reviewing.");
        if (next.companyId !== null) assert(fresh.companies.some(c => c.id === next.companyId), "Choose an existing non-demo customer.");
      }
      if (next.companyId !== null) {
        const company = await resolveCompany(next.companyId);
        assert(company?.id === next.companyId && !company.isDemo, "Choose an existing non-demo customer.");
      }
      if (input.decision === "reviewed") validateReviewScope(draft.candidate, draft.source_present, draft.source_evidence, next);
      const state = input.decision === "save-draft" ? "pending-review" : input.decision;
      const after: Draft = (await client.query(`UPDATE customer_connector_drafts SET proposal=$2,review_state=$3,revision=revision+1,
        reviewed_by=$4,reviewed_at=CASE WHEN $4::text IS NULL THEN NULL ELSE now() END,updated_at=now() WHERE id=$1 RETURNING *`,
      [input.id, JSON.stringify(next), state, input.decision === "save-draft" ? null : actor])).rows[0];
      await audit(client, actor, input.decision === "save-draft" ? "edited" : input.decision, after, draft, null, input.note);
      return after;
    });
  }
  async function listCustomerDrafts(companyId: string, includeUnassigned = false) {
    assert(short(companyId, 100), "Explicit customer required.");
    const rows = (await db.query(`SELECT * FROM customer_connector_drafts WHERE proposal->>'companyId'=$1
      ${includeUnassigned ? "OR (proposal->>'companyId' IS NULL AND candidate->>'companyId' IS NULL)" : ""}
      ORDER BY id LIMIT 1001`, [companyId])).rows as Draft[];
    assert(rows.length <= 1000, "Customer draft limit exceeded; refine the review before reading.");
    return rows;
  }
  async function reviewCurrentDraft(input: Parameters<typeof reviewDraft>[0], actor: string, collect: () => Promise<Preview>) {
    assert(typeof collect === "function", "Trusted metadata collector required.");
    // The fresh preview resolves company identity inside the registry transaction.
    return reviewDraft(input, actor, async id => ({ id }), collect);
  }
  return { importPreview, reviewDraft, reviewCurrentDraft, listCustomerDrafts };
}
