import type { Pool } from "pg";
import type { buildConnectorPreview, ConnectorCandidate } from "./customer-connector-preview";
import { connectorDraftEvidence, proposal, validatePreview, validateReviewScope, type ConnectorProposal } from "./customer-connector-drafts";

type Preview = ReturnType<typeof buildConnectorPreview>;
export type BindingInput = {
  candidateId: string; companyId: string; candidateHash: string; expectedRevision: number;
  decision: "save-draft" | "reviewed" | "dismissed"; proposal: ConnectorProposal; note: string;
};
type BindingRow = {
  candidate_id: string; company_id: string; candidate_hash: string; proposal: ConnectorProposal;
  revision: number; review_state: string; enabled: false; reviewed_by: string | null; reviewed_at: string | Date | null;
};
type BindingExportItem = {
  candidateId: string; state: string; revision: number; enabled: boolean; assignmentRequest: BindingInput | null;
  provider?: string; connectionRef?: string; capabilities?: ConnectorCandidate["capabilities"];
  sourcePresent?: boolean; importRequired?: boolean;
};
const assert = (value: unknown, message: string): void => { if (!value) throw new Error(message); };
const validCompany = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(value);
function snapshot(row: BindingRow) {
  return { candidateId: row.candidate_id, companyId: row.company_id, candidateHash: row.candidate_hash,
    proposal: row.proposal, revision: row.revision, reviewState: row.review_state, enabled: false,
    reviewedBy: row.reviewed_by, reviewedAt: row.reviewed_at };
}
function inputValue(input: BindingInput) {
  const keys = ["candidateId","companyId","candidateHash","expectedRevision","decision","proposal","note"];
  assert(input && typeof input === "object" && Object.keys(input).length === keys.length && Object.keys(input).every(k => keys.includes(k)), "Unexpected binding fields.");
  assert(validCompany(input.companyId) && /^[a-f0-9]{64}$/.test(input.candidateId) && /^[a-f0-9]{64}$/.test(input.candidateHash), "Valid customer and source evidence are required.");
  assert(Number.isSafeInteger(input.expectedRevision) && input.expectedRevision >= 0, "Valid binding revision required.");
  assert(["save-draft","reviewed","dismissed"].includes(input.decision), "Invalid binding decision.");
  assert(typeof input.note === "string" && input.note.trim().length > 0 && input.note.length <= 1000 && !/[\x00-\x1f\x7f]/.test(input.note), "A non-secret binding review note is required.");
  const next = proposal(input.proposal);
  assert(next.companyId === input.companyId, "Binding customer cannot be changed.");
  return next;
}

// Operator-only until runtime routing/activation have their own verified gate.
// No pool singleton, schema initializer, worker, secret loading or provider calls.
export function createConnectorBindingStore(db: Pick<Pool,"connect">) {
  async function save(input: BindingInput, actor: string, collect: () => Promise<Preview>) {
    const next = inputValue(input);
    assert(typeof actor === "string" && actor.length > 0 && actor.length <= 160 && !/[\x00-\x1f\x7f]/.test(actor), "Trusted operator identity required.");
    assert(typeof collect === "function", "Trusted metadata collector required.");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SELECT pg_advisory_xact_lock(716301, 1)");
      const fresh = await collect(); validatePreview(fresh);
      assert(fresh.companies.some(c => c.id === input.companyId), "Choose an existing non-demo customer.");
      const parent = (await client.query("SELECT * FROM customer_connector_drafts WHERE id=$1 FOR SHARE", [input.candidateId])).rows[0];
      assert(parent && parent.candidate_hash === input.candidateHash, "Source metadata changed; import a fresh preview before reviewing.");
      const current = fresh.candidates.find(c => c.id === input.candidateId);
      assert(current ? parent.source_present && connectorDraftEvidence(current,fresh.candidates).candidateHash === parent.candidate_hash : !parent.source_present,
        "Source metadata changed; import a fresh preview before reviewing.");
      const candidate: ConnectorCandidate = current ?? parent.candidate;
      assert(!candidate.companyId || candidate.companyId === input.companyId, "This source belongs to a different customer.");
      assert(candidate.connectionRef && candidate.evidence !== "completed-import", "Historical data cannot be assigned as a connection.");
      const before: BindingRow | undefined = (await client.query("SELECT * FROM customer_connector_bindings WHERE candidate_id=$1 AND company_id=$2 FOR UPDATE", [input.candidateId,input.companyId])).rows[0];
      assert((before?.revision ?? 0) === input.expectedRevision, "Binding changed; export current assignments before reviewing.");
      if (input.decision === "reviewed") validateReviewScope(candidate, !!current && parent.source_present, parent.source_evidence, next);
      const state = input.decision === "save-draft" ? "pending-review" : input.decision;
      const after: BindingRow = (await client.query(`INSERT INTO customer_connector_bindings
        (candidate_id,company_id,candidate_hash,proposal,revision,review_state,reviewed_by,reviewed_at)
        VALUES($1,$2,$3,$4,1,$5,$6,CASE WHEN $6::text IS NULL THEN NULL ELSE now() END)
        ON CONFLICT(candidate_id,company_id) DO UPDATE SET candidate_hash=EXCLUDED.candidate_hash,proposal=EXCLUDED.proposal,
        revision=customer_connector_bindings.revision+1,review_state=EXCLUDED.review_state,reviewed_by=EXCLUDED.reviewed_by,
        reviewed_at=EXCLUDED.reviewed_at,updated_at=now() RETURNING *`,
        [input.candidateId,input.companyId,input.candidateHash,JSON.stringify(next),state,input.decision === "save-draft" ? null : actor])).rows[0];
      await client.query(`INSERT INTO customer_connector_binding_audit(candidate_id,company_id,revision,actor,action,before_state,after_state,note)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [input.candidateId,input.companyId,after.revision,actor,input.decision,
        before ? JSON.stringify(snapshot(before)) : null,JSON.stringify(snapshot(after)),input.note]);
      await client.query("COMMIT"); return snapshot(after);
    } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; } finally {client.release();}
  }
  async function list(companyId: string, collect: () => Promise<Preview>) {
    assert(validCompany(companyId), "Explicit customer required.");
    const fresh = await collect(); validatePreview(fresh);
    assert(fresh.companies.some(c => c.id === companyId), "Choose an existing non-demo customer.");
    const client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      const rows = (await client.query(`SELECT d.id,d.candidate,d.candidate_hash,d.source_present,
        b.proposal AS binding_proposal,b.candidate_hash AS binding_hash,b.revision,b.review_state
        FROM customer_connector_drafts d LEFT JOIN customer_connector_bindings b ON b.candidate_id=d.id AND b.company_id=$1
        WHERE b.company_id=$1 OR d.candidate->>'companyId'=$1 OR d.candidate->>'companyId' IS NULL
        ORDER BY d.id LIMIT 1001`,[companyId])).rows;
      assert(rows.length <= 1000, "Customer binding limit exceeded.");
      const items = rows.flatMap<BindingExportItem>(row => {
        const current = fresh.candidates.find(c => c.id === row.id);
        // A moved source must not reveal the new customer's tenant, target or details.
        const ownershipChanged = current?.companyId && current.companyId !== companyId;
        if (ownershipChanged || row.candidate.companyId && row.candidate.companyId !== companyId) {
          return row.revision ? [{ candidateId:row.id, state:"ownership-changed", revision:row.revision, enabled:false, assignmentRequest:null }] : [];
        }
        const candidate: ConnectorCandidate = current ?? row.candidate;
        if (!candidate.connectionRef || candidate.evidence === "completed-import") return [];
        const hash = current ? connectorDraftEvidence(current,fresh.candidates).candidateHash : row.candidate_hash;
        const imported = row.source_present === !!current && row.candidate_hash === hash;
        const state = !imported || !current || row.binding_hash && row.binding_hash !== hash ? "needs-review" : row.review_state ?? "unassigned";
        return [{candidateId:row.id,provider:candidate.provider,connectionRef:candidate.connectionRef,capabilities:candidate.capabilities,
          state,revision:row.revision ?? 0,enabled:false,sourcePresent:!!current,importRequired:!imported,
          assignmentRequest:{candidateId:row.id,companyId,candidateHash:hash,expectedRevision:row.revision ?? 0,
            decision:"save-draft",note:"",proposal:row.binding_proposal ?? {companyId,tenantId:candidate.tenantId,datasets:[],targets:[],authority:"unassigned"}}}];
      });
      await client.query("COMMIT"); return {companyId,mode:"inactive-customer-bindings",items};
    } catch(error) {await client.query("ROLLBACK").catch(()=>{});throw error;} finally {client.release();}
  }
  return {save,list};
}
