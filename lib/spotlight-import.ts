import type { FalconTenant, SpotlightFinding } from "./crowdstrike";
import type { SpotlightRecord } from "./spotlight-record-store";

type CompanyBinding = { id: string; name: string };
export type SpotlightTenantSelection = {
  config: FalconTenant;
  companyId: string;
  tenantKey: string;
};

// An empty-body connector sync targets the sole named customer tenant. The
// unnamed primary tenant is never implicitly included in a customer import.
export function selectSpotlightTenant(
  configs: FalconTenant[],
  companies: CompanyBinding[],
  requestedCompanyId?: string,
): SpotlightTenantSelection {
  const named = configs.filter(config => Boolean(config.customerName?.trim()));
  if (!named.length) throw new Error("No named CrowdStrike customer tenant is configured.");
  if (!requestedCompanyId && named.length !== 1) {
    throw new Error("Choose a company ID when multiple CrowdStrike customer tenants are configured.");
  }
  const candidates = named.map(config => ({
    config,
    company: companies.find(company => company.name.trim().toLowerCase() === config.customerName!.trim().toLowerCase()),
  })).filter((item): item is { config: FalconTenant; company: CompanyBinding } => Boolean(item.company));
  const matches = requestedCompanyId
    ? candidates.filter(item => item.company.id === requestedCompanyId)
    : candidates;
  if (matches.length !== 1) {
    throw new Error("CrowdStrike customer tenant must match exactly one existing company.");
  }
  return { config: matches[0].config, companyId: matches[0].company.id, tenantKey: matches[0].company.id };
}

export type SpotlightImportProgress = {
  phase: "Starting" | "Fetching" | "Storing" | "Completing";
  tenant: string;
  fetched: number;
  stored: number;
};

export type SpotlightImportDependencies = {
  batches: (config: FalconTenant) => AsyncIterable<SpotlightFinding[]>;
  begin: (tenantKey: string) => Promise<string>;
  write: (runId: string, tenantKey: string, rows: SpotlightRecord[]) => Promise<number>;
  complete: (runId: string, tenantKey: string, expectedCount: number) => Promise<number>;
  fail: (runId: string, error: string) => Promise<void>;
  prune: (tenantKey: string) => Promise<void>;
};

export async function runSpotlightImport(
  selection: SpotlightTenantSelection,
  deps: SpotlightImportDependencies,
  onProgress: (progress: SpotlightImportProgress) => void,
): Promise<{ findingsImported: number; hostsAffected: number; skipped: number }> {
  let runId: string | undefined;
  let fetched = 0;
  let stored = 0;
  const hosts = new Set<string>();
  const progress = (phase: SpotlightImportProgress["phase"]) =>
    onProgress({ phase, tenant: selection.config.label, fetched, stored });
  progress("Starting");
  try {
    runId = await deps.begin(selection.tenantKey);
    await deps.prune(selection.tenantKey);
    progress("Fetching");
    for await (const batch of deps.batches(selection.config)) {
      const observedAt = new Date().toISOString();
      const rows: SpotlightRecord[] = batch.map(item => ({
        sourceId: item.id, tenantKey: selection.tenantKey, companyId: selection.companyId,
        hostname: item.hostname, localIp: item.localIp, externalIp: item.externalIp,
        cve: item.cve, severity: item.severity, status: item.status,
        description: item.description, remediation: item.remediation,
        observedAt, raw: item.raw,
      }));
      for (const item of batch) {
        const host = item.hostname || item.localIp;
        if (host) hosts.add(host);
      }
      fetched += batch.length;
      progress("Storing");
      stored += await deps.write(runId, selection.tenantKey, rows);
      progress("Fetching");
      // Give status and health requests a chance to run between CPU work.
      await new Promise<void>(resolve => setImmediate(resolve));
    }
    progress("Completing");
    const exactCount = await deps.complete(runId, selection.tenantKey, fetched);
    // Promotion has committed. Cleanup can continue without holding the
    // visible sync result open; the next run retries it if interrupted.
    void deps.prune(selection.tenantKey).catch(error => {
      console.error("[spotlight] old generation cleanup failed:", error);
    });
    return { findingsImported: exactCount, hostsAffected: hosts.size, skipped: 0 };
  } catch (error) {
    if (runId) await deps.fail(runId, error instanceof Error ? error.message : String(error)).catch(() => {});
    throw error;
  }
}
