// Shared JSON contract. No credentials or database code in this client-safe file.
export type AssetCoverageSnapshot = {
  queryId: "asset-coverage";
  collectedAt: string;
  results: { managed: number; unmanaged: number; coverage_pct: number | null };
};

export type ElasticCoverageView = {
  mode: "live" | "sample" | "unconfigured" | "empty" | "unavailable";
  snapshot: AssetCoverageSnapshot | null;
};

// Additional queries get their own validators and panels; the browser never
// supplies arbitrary ES|QL.
export function parseAssetCoverage(value: unknown, now = Date.now()): AssetCoverageSnapshot {
  if (!value || typeof value !== "object") throw new Error("Expected an object.");
  const body = value as Record<string, unknown>;
  if (body.queryId !== "asset-coverage") throw new Error("Unknown queryId.");
  if (typeof body.collectedAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(body.collectedAt)) {
    throw new Error("collectedAt must be an ISO UTC timestamp.");
  }
  const time = Date.parse(body.collectedAt);
  if (!Number.isFinite(time) || time > now + 5 * 60_000) throw new Error("Invalid collection time.");
  if (!body.results || typeof body.results !== "object") throw new Error("Missing results.");
  const results = body.results as Record<string, unknown>;
  const { managed, unmanaged, coverage_pct: percentage } = results;
  if (typeof managed !== "number" || !Number.isSafeInteger(managed) || managed < 0 ||
      typeof unmanaged !== "number" || !Number.isSafeInteger(unmanaged) || unmanaged < 0 ||
      !Number.isSafeInteger(managed + unmanaged)) {
    throw new Error("Counts must be non-negative safe integers.");
  }
  const total = managed + unmanaged;
  const expected = total === 0 ? null : Math.round(managed * 1000 / total) / 10;
  if (expected === null ? percentage !== null :
      typeof percentage !== "number" || !Number.isFinite(percentage) || Math.abs(percentage - expected) > 0.000001) {
    throw new Error("coverage_pct must match the counts, rounded to one decimal (null for no assets).");
  }
  return { queryId: "asset-coverage", collectedAt: new Date(time).toISOString(),
    results: { managed, unmanaged, coverage_pct: expected } };
}
