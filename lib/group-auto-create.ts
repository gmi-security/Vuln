import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { createGroupTicket, readGroupTicket, reviewGroupTicket, setGroupTicketPriority } from "./patch-group-ticket-store";
import { runWithConcurrency } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DashboardError } from "./elastic-dashboard";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { cwPrioritiesBySort, type CWOption } from "./connectwise-client";
import { targetPriorityForSwath } from "./group-ticket-priority";
import { riskScoringDatabase } from "./risk-scoring-store";

// A remediation only skips the human review queue and goes straight to a
// ConnectWise ticket once it has an actual finding_risk row -- i.e. it has
// been through risk-refresh-scheduler's CISA KEV/EPSS/MISP/OpenCTI/IntelOwl
// enrichment pass and real-risk scoring (lib/finding-risk-compute.ts), not
// just CrowdStrike's own raw CVSS severity. This used to gate on
// worst_severity IN ('Critical','High') alone -- CrowdStrike assigns that
// the moment a CVE is discovered, before enrichment has ever run on it, so
// a brand-new, never-assessed Critical-by-CVSS finding would auto-create a
// real ConnectWise ticket with no KEV/EPSS/threat-intel signal behind it at
// all. Gating on finding_risk's effective_swath instead means: no row yet
// (enrichment hasn't caught up for this tenant/CVE) -> leave it for a
// human, same as an unmapped customer always has been -- "no data yet"
// means no guess, not a default yes.
//
// This also fixes the two-incompatible-scales problem the old max_risk
// gate had: CrowdStrike-sourced groups and stored-findings-sourced groups
// used to be scored on different, non-comparable scales (max_risk was
// Finding.realRisk's bounded 0-100 score for one and an unrelated uncapped
// additive score for the other), so only stored-findings could safely use
// the risk-based path. finding_risk's effective_swath (lib/risk-scoring.ts)
// is the one composite scale every source already gets scored on by the
// same risk-refresh pass, so this gate -- and the resulting ticket
// priority below -- now applies identically regardless of source.
//
// This only fires for a customer once a human has manually created at
// least one ticket for them: that's what teaches patch_customer_routing
// which ConnectWise company/board/team is correct (see the
// routing-learning step in runCreation, patch-group-ticket-store.ts).
const ACTOR = "auto-create";
// Swath 1-2: the two most urgent RBVM tiers (effective_swath>=800 or >=600
// composite score -- see risk-scoring.ts's DEFAULT_SWATH_THRESHOLDS).
// calculateSwath already folds CISA KEV / active-exploitation / ransomware
// association into an emergency elevation even when the raw composite score
// alone wouldn't clear threshold, so no separate KEV/CVSS check is needed
// on top of this -- Swath already is that check.
const ELIGIBLE_SWATH = 2;
// Pilot scope: only this customer, by explicit request, while auto-create is
// validated. Expand PILOT_COMPANY_IDS once it's proven out.
const PILOT_COMPANY_IDS = new Set([ATLAS_REPORTING_COMPANY_ID]);
// Paused 2026-09-29 while Atlas asked to hold new tickets until Automate
// caught up; unpaused the same day 4:22pm on Jim/Mark's direction -- client
// visibility into open vulns creates an obligation to ticket them, patching
// readiness doesn't change that.
//
// Re-paused 2026-10-08: auto-create was firing on raw CrowdStrike CVSS
// severity alone (worst_severity IN ('Critical','High')) with no check that
// the finding had actually been through risk-refresh-scheduler's KEV/EPSS/
// threat-intel enrichment pass -- see finding_risk / risk-scoring-store.ts.
// That produced real ConnectWise tickets for findings nobody had verified
// were actually high-risk, not just high-CVSS. Holding new auto-creates
// until the gate checks finding_risk instead of (or in addition to) raw
// severity. Gates both entry points (the 15-minute scheduler and "Run
// auto-create now"), not the autoCreateHighSeverityTickets logic itself, so
// flipping this is the only thing that changes. Priority backfill and
// closure-validation were never gated by this -- neither of those creates a
// new ticket, so they keep running normally.
export const ATLAS_AUTO_CREATE_PAUSED = true;

type Counts = { checked: number; created: number; errors: number; notYetEnriched: number };

// Ticket creation is async (runCreation runs in the background); this polls
// the draft's own row for a confirmed ticket_id before setting priority,
// rather than guessing at timing. Gives up (not an error -- the ticket
// itself may still be fine) if it never lands within the window.
async function waitForTicketId(id: string, timeoutMs = 60_000): Promise<number | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { request } = await readGroupTicket(id);
    if (request.ticketId) return request.ticketId;
    if (!["prepared", "creating"].includes(request.state)) return null; // failed/uncertain -- stop waiting
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return null;
}

// finding_risk is keyed by (tenant_key=our own companyId, cve, host_key) --
// NOT by CrowdStrike's own tenant CID, which is what this table's own
// tenant_id column holds for CrowdStrike-sourced groups (see the comment on
// cidToCompany in lib/store.ts: "no stored CrowdStrike cid -> companyId
// mapping anywhere in this app -- finding_risk's tenant_key is already our
// own companyId, not CrowdStrike's cid"). Joining on tenant_id here would
// silently match zero rows for every CrowdStrike-sourced group and block
// them forever -- app_company_id is the only correct key for this lookup,
// for either source, since stored-findings groups already use companyId as
// their tenant_id too.
//
// Null means "no finding_risk row yet for any of these CVEs" -- enrichment
// hasn't caught up, not "definitely low risk" -- the caller must treat that
// as ineligible, the same as an unmapped customer.
type DeviceCve = { cid: string; hostId: string; cve: string };
async function enrichedSwathFor(
  appCompanyId: string,
  cves: string[],
  deviceCves?: DeviceCve[] | null,
  source?: string | null,
): Promise<number | null> {
  if (!cves?.length) return null;
  const riskDb = await riskScoringDatabase();
  if (deviceCves?.length) {
    // Host-scoped path: only finding_risk rows for the exact (host_key, cve)
    // pairs in this draft's packet matter. Without this, a single KEV-listed
    // host elsewhere in the tenant that happens to share a CVE with this
    // draft would pull the whole group's swath to 1 and auto-create a ticket
    // for 199 unrelated devices that may never have been enriched at all.
    // Defender findings use a "defender:" tenant_key prefix; CrowdStrike
    // findings use the plain companyId.
    const tenantKey = source === "stored-findings" ? `defender:${appCompanyId}` : appCompanyId;
    const row = (await riskDb.query(
      `SELECT min(effective_swath) AS swath FROM finding_risk
       WHERE tenant_key=$1 AND source_open AND verification_status != 'verified_remediated'
       AND (host_key,cve) IN (SELECT "hostId",cve FROM jsonb_to_recordset($2::jsonb) s(cid TEXT,"hostId" TEXT,cve TEXT))`,
      [tenantKey, JSON.stringify(deviceCves)],
    )).rows[0] as { swath: number | null };
    return row.swath;
  }
  // No per-host data available in the packet: fall back to CVE-only lookup.
  const row = (await riskDb.query(
    `SELECT min(effective_swath) AS swath FROM finding_risk
     WHERE tenant_key=$1 AND cve = ANY($2::text[]) AND source_open AND verification_status != 'verified_remediated'`,
    [appCompanyId, cves],
  )).rows[0] as { swath: number | null };
  return row.swath;
}

export async function autoCreateHighSeverityTickets(): Promise<Counts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, created: 0, errors: 0, notYetEnriched: 0 };
  const db = await patchTicketDatabase();
  // Only the newest pending draft per remediation+tenant(+customer) -- the
  // same ranking group-draft-dedup.ts uses to decide what's stale. Without
  // this, a slower dedup sweep tick could still be racing to dismiss an
  // older duplicate at the same moment this auto-creates it. Scoped to the
  // pilot customer(s) in SQL now (previously filtered in JS below) so a
  // tenant outside the pilot never even gets pulled into app code --
  // whether a candidate is actually enrichment-eligible is decided per-row
  // further down, since that requires a lookup against a different database.
  const rows = (await db.query(`
    WITH ranked AS (
      SELECT id, cves, packet->>'appCompanyId' AS app_company_id,
        packet->>'source' AS source, packet->'deviceCves' AS device_cves,
        ROW_NUMBER() OVER (
        PARTITION BY remediation_id, tenant_id, packet->>'appCompanyId' ORDER BY prepared_at DESC
      ) AS rn
      FROM patch_group_ticket_requests
      WHERE state='prepared' AND review_state='pending' AND packet->>'appCompanyId' = ANY($1::text[])
    )
    SELECT id, cves, app_company_id, source, device_cves FROM ranked WHERE rn = 1
  `, [Array.from(PILOT_COMPANY_IDS)])).rows as { id: string; cves: string[]; app_company_id: string | null; source?: string | null; device_cves?: DeviceCve[] | null }[];
  if (!rows.length) return { checked: 0, created: 0, errors: 0, notYetEnriched: 0 };
  const routings = (await db.query("SELECT app_company_id, company_id, board_id, team_id FROM patch_customer_routing"))
    .rows as { app_company_id: string; company_id: number; board_id: number; team_id: number | null }[];
  const routingByCompany = new Map(routings.map((r) => [r.app_company_id, r]));
  // Most-urgent-first; fetched once and reused for every ticket this pass.
  // Missing/unreachable never blocks ticket creation -- it just means the
  // priority stays whatever the board's default is, same as before this
  // existed, rather than failing the whole thing. The failure itself is
  // still worth keeping visible though (see prioritiesFetchError below) --
  // this used to vanish into an indistinguishable empty array.
  let priorities: CWOption[] = [];
  let prioritiesFetchError: string | null = null;
  try {
    priorities = await cwPrioritiesBySort(saved.value);
  } catch (err) {
    prioritiesFetchError = err instanceof Error ? err.message : String(err);
  }
  let created = 0, errors = 0, notYetEnriched = 0;
  await runWithConcurrency(rows, 3, async (row) => {
    if (!row.app_company_id || !PILOT_COMPANY_IDS.has(row.app_company_id)) return; // defensive; SQL above already scopes to the pilot
    const routing = routingByCompany.get(row.app_company_id);
    if (!routing) return; // no known-good routing for this customer yet -- leave it for a human
    const swath = await enrichedSwathFor(row.app_company_id, row.cves, row.device_cves, row.source).catch(() => null);
    if (swath == null || swath > ELIGIBLE_SWATH) { if (swath == null) notYetEnriched++; return; } // not enriched yet, or enriched but not urgent -- leave it for a human
    try {
      await reviewGroupTicket(row.id, "approve", ACTOR);
      const read = await readGroupTicket(row.id, true);
      if (!read.group) throw new DashboardError("Prepared consolidation is missing its packet.");
      await createGroupTicket(row.id, {
        routing: { companyId: routing.company_id, boardId: routing.board_id, ...(routing.team_id ? { teamId: routing.team_id } : {}) },
        title: read.group.ticketTitle, body: read.group.ticketBody, connectionRevision: saved.revision,
      }, ACTOR);
      created++;
      // The ticket should assert its own severity immediately, not wait
      // days for SLA escalation to notice -- Swath 1 (the most urgent RBVM
      // tier, the same one driving the gate above) gets the top priority,
      // Swath 2 the next one down. Never lets a priority-setting problem
      // undo an otherwise-successful ticket creation.
      const effectiveSeverity: "Critical" | "High" = swath === 1 ? "Critical" : "High";
      const target = targetPriorityForSwath(swath as 1 | 2, priorities);
      if (target) {
        const ticketId = await waitForTicketId(row.id);
        if (ticketId) {
          // A failure here used to vanish silently -- a real Critical
          // ticket could sit at the board's default priority indefinitely
          // with nothing recorded anywhere to say why. backfillTicketPriority
          // will retry it on the next pass (no ticket.priority.changed audit
          // means it never counts as already handled), but the reason for
          // the first failure is worth keeping visible in the meantime.
          await setGroupTicketPriority(row.id, target.id, ACTOR).catch(async (err) => {
            const message = err instanceof Error ? err.message : String(err);
            await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
              [row.id, `Ticket created, but asserting ${effectiveSeverity} priority failed: ${message}`]).catch(() => {});
          });
        } else {
          await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
            [row.id, `Ticket created, but its ticket_id didn't appear within 60s to assert ${effectiveSeverity} priority. The next priority backfill pass will retry.`]).catch(() => {});
        }
      } else if (prioritiesFetchError) {
        await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
          [row.id, `Ticket created, but couldn't fetch ConnectWise priorities to assert ${effectiveSeverity}: ${prioritiesFetchError}. The next priority backfill pass will retry.`]).catch(() => {});
      }
    } catch {
      errors++; // one draft failing (routing went stale, connection changed) must not block the rest
    }
  });
  console.error(`[group-auto-create] checked=${rows.length} created=${created} notYetEnriched=${notYetEnriched} errors=${errors}`);
  return { checked: rows.length, created, errors, notYetEnriched };
}

const runtime = globalThis as typeof globalThis & { __groupAutoCreate?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__groupAutoCreate ??= {};

export function startGroupAutoCreateScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working || ATLAS_AUTO_CREATE_PAUSED) return;
    state.working = autoCreateHighSeverityTickets().then(
      () => {},
      (err) => console.error("[group-auto-create] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
