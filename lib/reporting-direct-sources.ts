import type { ElasticDashboard } from "./elastic-dashboard";
import type { PatchGroup } from "./patch-request";

// The current deployment has one customer with saved direct source tiles.
// This boundary is kept server-side so other app customers never receive them.
export const ATLAS_REPORTING_COMPANY_ID = "CO-147284";
export const hasDirectReportingSources = (companyId: string) => companyId === ATLAS_REPORTING_COMPANY_ID;

export function emptyReportingDashboard(canManage: boolean): ElasticDashboard {
  return { canManage, storageReady: true, connected: false, crowdstrike: { connected: false }, queries: [] };
}

export function directSourcesForCustomer(companyId: string, dashboard: ElasticDashboard, verifiedTileIds = ""): ElasticDashboard {
  if (!hasDirectReportingSources(companyId)) return { ...dashboard, connected: false,
    crowdstrike: { connected: false }, queries: [] };
  const allowed = new Set(verifiedTileIds.split(",").map(id => id.trim()).filter(Boolean));
  return { ...dashboard, queries: dashboard.queries.filter(query => allowed.has(query.id)) };
}

export function atlasFalconReviewPacket<T extends Pick<PatchGroup, "source" | "tenantId">>(group: T, verifiedTenantIds: string[]): T & { appCompanyId?: string } {
  return verifiedTenantIds.includes(group.tenantId.toLowerCase())
    ? { ...group, appCompanyId: ATLAS_REPORTING_COMPANY_ID } : { ...group };
}
