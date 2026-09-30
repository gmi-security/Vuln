import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { autoCreateHighSeverityTickets, ATLAS_AUTO_CREATE_PAUSED } from "@/lib/group-auto-create";
import { backfillWorstSeverity } from "@/lib/group-severity-backfill";
import { backfillAppCompanyId, backfillCustomerRouting } from "@/lib/group-company-backfill";
import { backfillTicketPriority } from "@/lib/group-priority-backfill";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    // Self-healing: catch up any draft still missing worst_severity or
    // appCompanyId, and seed routing from an already-created ticket if
    // nothing's taught it yet, before checking eligibility -- so a manual
    // run never misses a draft that's only stale on paper.
    await Promise.all([backfillWorstSeverity(), backfillAppCompanyId(), backfillCustomerRouting()]);
    // Priority backfill only touches tickets that already exist -- it never
    // creates one, so it keeps running even while creation itself is paused.
    const [created, priority] = await Promise.all([
      ATLAS_AUTO_CREATE_PAUSED ? Promise.resolve({ checked: 0, created: 0, errors: 0 }) : autoCreateHighSeverityTickets(),
      backfillTicketPriority(),
    ]);
    return dashboardJson({ ...created, paused: ATLAS_AUTO_CREATE_PAUSED, priorityBackfill: priority });
  } catch (error) { return dashboardFailure(error); }
}
