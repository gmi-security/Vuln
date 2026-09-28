import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readDashboard, triggerRefresh } from "@/lib/elastic-dashboard-store";
export const dynamic = "force-dynamic";
// The shared saved-tile dashboard (CVE-devices, patch-worklist, and the
// patch-consolidation/ticket-cutting flow built on top of them) has always
// been organization-wide, scoped by CrowdStrike tenant inside a query, not
// by GMI customer — restoring it here after it was briefly narrowed to only
// return data for one specific customer, which made ticket cutting and
// tracking unreachable for every other customer. Atlas's own additionally
// verified, customer-scoped saved tiles remain available separately via
// /api/elastic-dashboard/customer-tiles.
export async function GET() {
  try {
    const access = await dashboardAccess();
    triggerRefresh();
    return dashboardJson(await readDashboard(access.canManage));
  } catch (error) { return dashboardFailure(error); }
}
