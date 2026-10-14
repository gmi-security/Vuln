import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { applicationDatabase } from "@/lib/persist";
import { readSavedApplicationCompanies } from "@/lib/db/connector-metadata.mjs";
import { createCustomerSavedSources, savedSourcePolicy, SavedSourceError } from "@/lib/customer-saved-sources";
import { createDefenderSourceReader } from "@/lib/defender-source-read-model";
import { createSpotlightSummaryStore } from "@/lib/spotlight-summary-store";
import { createSavedSourceBindingSelector } from "@/lib/customer-saved-source-bindings";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    if (!remediationUiEnabled() || process.env.VULN_SAVED_SOURCE_READS !== "true") throw new DashboardError("Not found", 404);
    const mode = process.env.VULN_SAVED_SOURCE_SELECTION || "allowlist";
    if (mode !== "allowlist" && mode !== "registry") throw new DashboardError("Saved source selection is invalid.", 503);
    const policy = mode === "allowlist" ? savedSourcePolicy(process.env.VULN_SAVED_SOURCE_READ_CUSTOMERS) : {};
    const db = applicationDatabase();
    if (!db) throw new DashboardError("Saved source storage is unavailable.", 503);
    const service = createCustomerSavedSources({policy,
      ...(mode === "registry" ? { select: createSavedSourceBindingSelector(db, process.env) } : {}), companies: async () => {
      const client = await db.connect();
      try { return await readSavedApplicationCompanies(client); } finally { client.release(); }
    }, read: {defender: createDefenderSourceReader(db), crowdstrike: createSpotlightSummaryStore(db).read}});
    return dashboardJson(await service.get(new URL(request.url).searchParams));
  } catch (error) {
    return dashboardFailure(error instanceof SavedSourceError ? new DashboardError(error.message, error.status) : error);
  }
}
