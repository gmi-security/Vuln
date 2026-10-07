import type { FalconTenant, SpotlightFinding } from "./crowdstrike";
import type { SpotlightRecord } from "./spotlight-record-store";

// Duplicated from lib/company-name.ts rather than imported: this module is
// loaded with zero runtime dependencies elsewhere (see
// tests/spotlight-import.test.mjs, which links it against a stub that
// throws on any import), so it can't pull in even a trivial pure helper
// from another file. Keep in sync if the shared version changes.
function normalizeCompanyName(name: string): string {
  return name
    .normalize("NFKC")
    .replace(/[‘’ʼ]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

// Duplicated from lib/company-name.ts for the same zero-runtime-dependency
// reason as normalizeCompanyName above -- keep in sync if the shared version
// changes. Catches the "Atlas Healthcare Partners" vs "Atlas HealthCare"
// class of bug: an exact-name match alone can't tell "the only company with
// this name" apart from "the only company with this EXACT name, but there's
// a near-duplicate sitting right next to it" -- which is exactly how a
// CrowdStrike Falcon tenant configured for "Atlas HealthCare" ended up
// importing into a second, near-empty company instead of the real "Atlas
// Healthcare Partners" record.
function findNearDuplicateCompanyName<T extends { id: string; name: string }>(
  targetName: string,
  companies: T[],
  excludeId?: string,
): T | undefined {
  const target = normalizeCompanyName(targetName);
  return companies.find((c) => {
    if (c.id === excludeId) return false;
    const name = normalizeCompanyName(c.name);
    if (name === target) return false;
    const [shorter, longer] = name.length <= target.length ? [name, target] : [target, name];
    return longer.startsWith(`${shorter} `);
  });
}

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
    company: companies.find(company => normalizeCompanyName(company.name) === normalizeCompanyName(config.customerName!)),
  })).filter((item): item is { config: FalconTenant; company: CompanyBinding } => Boolean(item.company));
  const matches = requestedCompanyId
    ? candidates.filter(item => item.company.id === requestedCompanyId)
    : candidates;
  if (matches.length !== 1) {
    throw new Error("CrowdStrike customer tenant must match exactly one existing company.");
  }
  const matched = matches[0];
  const nearDuplicate = findNearDuplicateCompanyName(matched.company.name, companies, matched.company.id);
  if (nearDuplicate) {
    throw new Error(
      `CrowdStrike tenant "${matched.config.customerName}" matched company "${matched.company.name}" (${matched.company.id}), but "${nearDuplicate.name}" (${nearDuplicate.id}) looks like the same company under a different name. Refusing to sync until this is resolved -- merge the duplicate or fix the configured tenant name, so data doesn't land under the wrong company.`,
    );
  }
  return { config: matched.config, companyId: matched.company.id, tenantKey: matched.company.id };
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
