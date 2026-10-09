/** Saved-source reads only. This is not a cross-source authority or risk model. */
export const sourceSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"] as const;
export type SourceSeverity = typeof sourceSeverities[number];
export type SeverityCounts = Record<SourceSeverity, number>;
export function emptySeverityCounts(): SeverityCounts {
  return Object.fromEntries(sourceSeverities.map(key => [key, 0])) as SeverityCounts;
}
export type CustomerSourceReadRequest = {
  // Caller must authorize this explicit application company ID before invoking an adapter.
  companyId: string;
  now: Date;
  staleAfterMs: number;
  offset?: number;
  limit?: number;
};
export type SourceGeneration = {
  id: string;
  connectionRevision: number;
  importRevision: number;
  revisionMatches: boolean;
  completedAt: string;
  freshness: "within-window" | "stale" | "unknown";
  ageMs: number | null;
  // Completion does not establish when every endpoint was assessed.
  clock: "import-completion";
};
export type SourceCveRow = {
  cve: string;
  severity: SourceSeverity;
  cvss: number | null;
  affectedDevices: number;
  sourceInstances: number;
};
export type CustomerSourceRead = {
  version: 1;
  companyId: string;
  source: "defender";
  scope: "saved-source-generation";
  // No credentials, tenant identifiers, vendor payloads or import error messages.
  latestAttempt: { status: "queued" | "running" | "succeeded" | "failed"; startedAt: string; finishedAt: string | null } | null;
} & ({
  state: "not-installed" | "not-configured" | "no-completed-import" | "inconsistent";
  generation: null;
  summary: null;
  cves: null;
} | {
  state: "available";
  generation: SourceGeneration;
  summary: {
    sourceInstances: number;
    deviceCveFindings: number;
    uniqueCves: number;
    affectedDevices: number;
    inventoryDevices: number;
    severity: { sourceInstances: SeverityCounts; uniqueCves: SeverityCounts };
  };
  cves: { rows: SourceCveRow[]; total: number; offset: number; limit: number };
});

export function validateSourceRead(request: CustomerSourceReadRequest) {
  const { companyId, now, staleAfterMs, offset = 0, limit = 50 } = request;
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(companyId) ||
      !Number.isFinite(now.getTime()) || !Number.isSafeInteger(staleAfterMs) || staleAfterMs <= 0 ||
      !Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new Error("Invalid customer source read request.");
  }
  return { companyId, now, staleAfterMs, offset, limit };
}

export function importFreshness(completedAt: string, now: Date, staleAfterMs: number): Pick<SourceGeneration, "freshness" | "ageMs"> {
  const ageMs = now.getTime() - new Date(completedAt).getTime();
  if (!Number.isFinite(ageMs) || ageMs < 0) return { freshness: "unknown", ageMs: null };
  return { freshness: ageMs > staleAfterMs ? "stale" : "within-window", ageMs };
}
