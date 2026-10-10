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
  // Server-selected binding only; never populated from query parameters.
  defenderConnection?: { tenantId: string; revision: number };
};
export type SourceGeneration = {
  id: string;
  connectionRevision: number | null;
  importRevision: number | null;
  revisionMatches: boolean | null;
  completedAt: string;
  freshness: "within-window" | "stale" | "unknown";
  ageMs: number | null;
  // Completion does not establish when every endpoint was assessed.
  clock: "import-completion";
  countVerification: "summary-reconciled" | "import-count-reconciled" | "completion-marker-only";
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
  source: "defender" | "crowdstrike";
  scope: "saved-source-generation";
  projection?: { state: "ready" | "pending"; currentImportId: string; builtAt: string | null; modelVersion: number };
  definition: {
    instanceUnit: "device-cve-software-version" | "spotlight-finding";
    severityBasis: "source-cvss";
    suppression: "not-recorded" | "exclude-confirmed-suppressed";
  };
  // No credentials, tenant identifiers, vendor payloads or import error messages.
  latestAttempt: { status: "queued" | "running" | "succeeded" | "failed"; startedAt: string; finishedAt: string | null } | null;
} & ({
  state: "not-installed" | "not-configured" | "no-completed-import" | "summary-pending" | "inconsistent";
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
    inventoryDevices: number | null;
    // Coverage qualifiers for the included CVE findings; unsupported measurements are null.
    unknownSuppressionInstances: number | null;
    excludedSuppressedInstances: number | null;
    excludedNonCveInstances: number;
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
  if (request.defenderConnection && (!request.defenderConnection.tenantId ||
      !Number.isSafeInteger(request.defenderConnection.revision) || request.defenderConnection.revision < 1))
    throw new Error("Invalid saved connection guard.");
  return { companyId, now, staleAfterMs, offset, limit };
}

export function importFreshness(completedAt: string, now: Date, staleAfterMs: number): Pick<SourceGeneration, "freshness" | "ageMs"> {
  const ageMs = now.getTime() - new Date(completedAt).getTime();
  if (!Number.isFinite(ageMs) || ageMs < 0) return { freshness: "unknown", ageMs: null };
  return { freshness: ageMs > staleAfterMs ? "stale" : "within-window", ageMs };
}
