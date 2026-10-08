import type { ElasticDashboard } from "./elastic-dashboard";
import type { PatchGroup } from "./patch-request";

// The current deployment has one customer with saved direct source tiles.
// This boundary is kept server-side so other app customers never receive them.
export const ATLAS_REPORTING_COMPANY_ID = "CO-147284";
export const hasDirectReportingSources = (companyId: string) => companyId === ATLAS_REPORTING_COMPANY_ID;

// Explicit, server-managed ownership of reviewed saved queries. Never infer
// ownership from a global connection, tile title or whichever customer is open.
export function customerReportingTileIds(companyId: string, configured = "", atlasIds = ""): string[] {
  const assignments = new Map<string,string[]>();
  if (atlasIds.trim()) assignments.set(ATLAS_REPORTING_COMPANY_ID,atlasIds.split(",").map(id=>id.trim()).filter(Boolean));
  if (configured.trim()) {
    let parsed: unknown;
    try { parsed = JSON.parse(configured); } catch { throw new Error("Invalid customer reporting tile assignments."); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid customer reporting tile assignments.");
    for (const [company,ids] of Object.entries(parsed)) {
      if (!company || !Array.isArray(ids) || ids.some(id=>typeof id !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(id)))
        throw new Error("Invalid customer reporting tile assignments.");
      assignments.set(company,[...new Set(ids)]);
    }
  }
  const owners = new Map<string,string>();
  for (const [company,ids] of assignments) for (const id of ids) {
    if (!/^[a-zA-Z0-9-]{1,64}$/.test(id) || (owners.has(id) && owners.get(id) !== company))
      throw new Error("Each reporting tile must have one verified customer owner.");
    owners.set(id,company);
  }
  return companyId ? assignments.get(companyId) ?? [] : [];
}

// Persisted ownership wins over legacy environment assignments, including null.
export function reportingTileCompanyId(query: { id:string; companyId?:string | null }, configured = "", atlasIds = ""): string | null {
  if (query.companyId !== undefined) return query.companyId;
  const companies = new Set([ATLAS_REPORTING_COMPANY_ID]);
  if (configured.trim()) {
    customerReportingTileIds("",configured,atlasIds); // Validate before reading keys.
    Object.keys(JSON.parse(configured)).forEach(company=>companies.add(company));
  }
  for (const company of companies) if (customerReportingTileIds(company,configured,atlasIds).includes(query.id)) return company;
  return null;
}

export function emptyReportingDashboard(canManage: boolean): ElasticDashboard {
  return { canManage, storageReady: true, connected: false, crowdstrike: { connected: false }, queries: [] };
}

export function directSourcesForCustomer(companyId: string, dashboard: ElasticDashboard, verifiedTileIds = "", configured = ""): ElasticDashboard {
  customerReportingTileIds(companyId,configured,verifiedTileIds);
  const queries = dashboard.storageReady ? dashboard.queries.filter(query => !!companyId && reportingTileCompanyId(query,configured,verifiedTileIds) === companyId &&
    (query.source === "crowdstrike" ? dashboard.crowdstrike?.connected : dashboard.connected)) : [];
  // No unrelated endpoint, region, status or cached result in the response.
  return { canManage:dashboard.canManage,storageReady:dashboard.storageReady,
    connected:queries.some(query=>query.source !== "crowdstrike"),
    crowdstrike:{connected:queries.some(query=>query.source === "crowdstrike")},queries,
    ...(dashboard.canManage ? {availableSources:dashboard.availableSources,unassignedTiles:dashboard.unassignedTiles} : {}) };
}

export function atlasFalconReviewPacket<T extends Pick<PatchGroup, "source" | "tenantId">>(group: T, verifiedTenantIds: string[]): T & { appCompanyId?: string } {
  return verifiedTenantIds.includes(group.tenantId.toLowerCase())
    ? { ...group, appCompanyId: ATLAS_REPORTING_COMPANY_ID } : { ...group };
}
