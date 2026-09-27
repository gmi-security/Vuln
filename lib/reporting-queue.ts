import { createHash, randomUUID } from "node:crypto";
import { patchTicketDatabase, activeTicketedPairs } from "./patch-ticket-store";
import { ensureHydrated, listCompanies, listFindings } from "./store";
import { buildStoredFindingGroups } from "./reporting-consolidation";
import { elasticVulnEnabled } from "./elastic-vuln-server";

const runtime = globalThis as typeof globalThis & { __reportingQueue?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__reportingQueue ??= {};

export async function refreshReportingQueue(): Promise<void> {
  const db = await patchTicketDatabase();
  const last = (await db.query("SELECT completed_at,scope_version FROM reporting_queue_runs WHERE id=1")).rows[0];
  if (last?.scope_version === 2 && Date.now() - new Date(last.completed_at).getTime() < 60 * 60_000) return;
  await ensureHydrated();
  const companies = listCompanies().filter(company => company.kind === "client" && !company.isDemo);
  const active = await activeTicketedPairs();
  const byCompany = new Map<string, ReturnType<typeof listFindings>>();
  const eligible = new Set(companies.map(company => company.id));
  for (const finding of listFindings()) {
    if (!eligible.has(finding.companyId)) continue;
    const rows = byCompany.get(finding.companyId) ?? [];
    rows.push(finding); byCompany.set(finding.companyId, rows);
  }
  const groups = companies.flatMap(company => buildStoredFindingGroups(company, byCompany.get(company.id) ?? [], active));
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804208)");
    const current = (await client.query("SELECT completed_at,scope_version FROM reporting_queue_runs WHERE id=1 FOR UPDATE")).rows[0];
    if (current?.scope_version === 2 && Date.now() - new Date(current.completed_at).getTime() < 60 * 60_000) { await client.query("COMMIT"); return; }
    for (const group of groups) {
      const scopeHash = createHash("sha256").update(JSON.stringify(group.deviceCves)).digest("hex");
      const prior = await client.query(`SELECT id FROM patch_group_ticket_requests
        WHERE remediation_id=$1 AND tenant_id=$2 AND scope_hash=$3 AND packet->>'source'='stored-findings' LIMIT 1`,
        [group.remediationId, group.tenantId, scopeHash]);
      if (prior.rowCount) continue;
      const id = randomUUID();
      await client.query(`INSERT INTO patch_group_ticket_requests
        (id,cves,remediation_id,tenant_id,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,finding_count,scope_hash)
        VALUES($1,$2::jsonb,$3,$4,'automatic reporting',now(),0,$5::jsonb,$6,$7,$8)`,
        [id, JSON.stringify(group.cves), group.remediationId, group.tenantId, JSON.stringify(group), group.deviceCount, group.findingCount, scopeHash]);
      await client.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,'automatic reporting','group.prepared')", [id]);
    }
    await client.query(`INSERT INTO reporting_queue_runs(id,completed_at,scope_version) VALUES(1,now(),2)
      ON CONFLICT(id) DO UPDATE SET completed_at=EXCLUDED.completed_at,scope_version=EXCLUDED.scope_version`);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

export function startReportingQueueScheduler() {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = refreshReportingQueue().catch(() => {
      console.error("[reporting-queue] Candidate generation could not complete.");
    }).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
