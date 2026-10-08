import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { createGroupTicket, readGroupTicket, reviewGroupTicket, setGroupTicketPriority } from "./patch-group-ticket-store";
import { runWithConcurrency } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DashboardError } from "./elastic-dashboard";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { cwPrioritiesBySort, type CWOption } from "./connectwise-client";
import { targetPriorityFor } from "./group-ticket-priority";

// Critical/High severity remediations, OR any stored-findings (scanner-
// sourced) remediation touching a real-risk-critical (KEV-listed, actively-
// exploited, or otherwise >= 80 composite score -- see lib/threat.ts's
// riskPriority buckets) finding regardless of raw CVSS severity, skip the
// human review queue and go straight to a ConnectWise ticket -- always
// through the consolidated group format, never the single-CVE path. This
// only fires for a customer once a human has manually created at least one
// ticket for them: that's what teaches patch_customer_routing which
// ConnectWise company/board/team is correct (see the routing-learning step
// in runCreation, patch-group-ticket-store.ts). No mapping yet means no
// guess -- the draft is left for a human, same as before. Anything below
// both thresholds is never touched here.
//
// The risk-score trigger is deliberately restricted to stored-findings:
// max_risk is populated from two incompatible scales depending on source --
// Finding.realRisk (lib/threat.ts's bounded 0-100 multiplicative score, what
// RISK_AUTO_CREATE_THRESHOLD is actually calibrated against) for
// stored-findings, but CrowdStrike-sourced groups carry an unrelated,
// uncapped ADDITIVE score (lib/crowdstrike-dashboard.ts's
// vulnerabilityRiskFromFields, max ~115) that crosses 80 far more easily --
// a realistic High-severity (not Critical) KEV-listed finding with CVSS 7.2
// scores ~84 on that scale alone. Applying the same threshold to it would
// auto-create and Critical-prioritize tickets well below the intended bar
// for the one real customer this runs against. Fix the CrowdStrike score's
// own calibration (or compute a real computeRealRisk-equivalent for it)
// before ever including it here.
const ACTOR = "auto-create";
// Matches lib/threat.ts's Critical riskPriority bucket exactly -- a group
// whose worst CVSS severity alone reads Medium/Low can still land here if
// one of its findings is KEV-listed or actively exploited on a
// critical/exposed asset, which is exactly the case raw severity misses.
// Only meaningful for stored-findings rows -- see the comment above.
const RISK_AUTO_CREATE_THRESHOLD = 80;
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

type Counts = { checked: number; created: number; errors: number };

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

export async function autoCreateHighSeverityTickets(): Promise<Counts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, created: 0, errors: 0 };
  const db = await patchTicketDatabase();
  // Only the newest pending draft per remediation+tenant(+customer) -- the
  // same ranking group-draft-dedup.ts uses to decide what's stale. Without
  // this, a slower dedup sweep tick could still be racing to dismiss an
  // older duplicate at the same moment this auto-creates it.
  const rows = (await db.query(`
    WITH ranked AS (
      SELECT id, packet->>'appCompanyId' AS app_company_id, worst_severity, max_risk,
        packet->>'source' AS source, ROW_NUMBER() OVER (
        PARTITION BY remediation_id, tenant_id, packet->>'appCompanyId' ORDER BY prepared_at DESC
      ) AS rn
      FROM patch_group_ticket_requests
      WHERE state='prepared' AND review_state='pending'
        AND (worst_severity IN ('Critical','High') OR (max_risk >= $1 AND packet->>'source'='stored-findings'))
    )
    SELECT id, app_company_id, worst_severity, max_risk, source FROM ranked WHERE rn = 1
  `, [RISK_AUTO_CREATE_THRESHOLD])).rows as { id: string; app_company_id: string | null; worst_severity: string | null; max_risk: number | null; source: string | null }[];
  if (!rows.length) return { checked: 0, created: 0, errors: 0 };
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
  let created = 0, errors = 0;
  await runWithConcurrency(rows, 3, async (row) => {
    if (!row.app_company_id || !PILOT_COMPANY_IDS.has(row.app_company_id)) return; // outside the pilot scope
    const routing = routingByCompany.get(row.app_company_id);
    if (!routing) return; // no known-good routing for this customer yet -- leave it for a human
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
      // days for SLA escalation to notice. Critical -> the top priority;
      // High -> the next one down. A stored-findings row whose raw CVSS
      // severity reads Medium or lower but whose max_risk crosses the
      // threshold is treated as Critical here too -- a KEV-listed or
      // actively-exploited finding on a critical/exposed asset deserves the
      // top slot regardless of what its CVSS alone says. Gated to
      // stored-findings for the same reason the SQL gate above is: a
      // CrowdStrike-sourced row's max_risk is on a different, uncapped scale
      // that crosses this threshold far more easily and would otherwise
      // over-prioritize merely-High-severity CrowdStrike tickets. Never lets
      // a priority-setting problem undo an otherwise-successful ticket
      // creation.
      const riskQualifies = row.source === "stored-findings" && (row.max_risk ?? 0) >= RISK_AUTO_CREATE_THRESHOLD;
      const effectiveSeverity: "Critical" | "High" = row.worst_severity === "Critical" || riskQualifies ? "Critical" : "High";
      const target = targetPriorityFor(effectiveSeverity, priorities);
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
  return { checked: rows.length, created, errors };
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
