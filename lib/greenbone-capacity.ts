import { vulnersBridgeConfig, type VulnersBridgeConfig } from "./vulners";
import type { ScannerCapacityProof } from "./external-scan-admission";

/**
 * The legacy GET /api/v1/scans endpoint is NOT trustworthy for capacity:
 * Vulners-v2 has returned only the final task from thousands of historical
 * tasks. Never infer an idle scanner from that endpoint.
 *
 * This strictly requires a future scanner-side aggregate endpoint, validated
 * against the COMPLETE gvmd task inventory. Until it is implemented and
 * verified on Vulners-v2, calls fail closed and cannot authorize a scan.
 */
const STATUS_KEYS = [
  "New", "Requested", "Queued", "Running", "Stop Requested",
  "Done", "Stopped", "Interrupted",
] as const;
type StatusKey = typeof STATUS_KEYS[number];

type CapacitySnapshot = {
  source: "gvmd";
  inventoryComplete: true;
  scannerHealthy: true;
  generatedAt: string;
  totalTasks: number;
  statusCounts: Record<StatusKey, number>;
};

export function validateGreenboneCapacitySnapshot(payload: unknown, clockMs = Date.now()): ScannerCapacityProof {
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("Greenbone capacity response is missing or malformed.");
  const p = payload as Record<string, unknown>;
  if (p.source !== "gvmd" || p.inventoryComplete !== true || p.scannerHealthy !== true)
    throw new Error("Greenbone scanner health or complete task inventory is unverified.");
  if (typeof p.generatedAt !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(p.generatedAt))
    throw new Error("Greenbone capacity timestamp is missing.");
  const ts = Date.parse(p.generatedAt);
  if (!Number.isFinite(clockMs) || !Number.isFinite(ts) || ts > clockMs || clockMs - ts > 30_000)
    throw new Error("Greenbone capacity snapshot is stale or future-dated.");
  if (!Number.isSafeInteger(p.totalTasks) || (p.totalTasks as number) < 0)
    throw new Error("Greenbone task total is invalid.");
  if (!p.statusCounts || typeof p.statusCounts !== "object" || Array.isArray(p.statusCounts))
    throw new Error("Greenbone status counts are missing.");
  const raw = p.statusCounts as Record<string, unknown>;
  if (Object.keys(raw).length !== STATUS_KEYS.length ||
      STATUS_KEYS.some(key => !Object.hasOwn(raw, key) ||
        !Number.isSafeInteger(raw[key]) || (raw[key] as number) < 0))
    throw new Error("Greenbone status counts are partial, unknown or invalid.");
  const counts = raw as Record<StatusKey, number>;
  const sum = STATUS_KEYS.reduce((total, key) => total + counts[key], 0);
  if (!Number.isSafeInteger(sum) || sum !== p.totalTasks)
    throw new Error("Greenbone complete-inventory total does not match status counts.");
  return {
    checkedAt: new Date(ts).toISOString(),
    healthy: true,
    activeTaskCount: counts.Running + counts["Stop Requested"],
    queuedTaskCount: counts.Queued,
    requestedTaskCount: counts.Requested,
  };
}

/**
 * Read-only GET; no retries, starts, scan creations, or credential logging.
 * The backend has to perform an exhaustive GVM query or authoritative
 * aggregate. Simply asserting inventoryComplete=true in a truncated list is
 * NOT acceptable and must be tested independently on the scanner host.
 */
export async function readVerifiedGreenboneCapacity(
  config: VulnersBridgeConfig | null = vulnersBridgeConfig(),
): Promise<ScannerCapacityProof> {
  if (!config?.baseUrl || !config.apiKey)
    throw new Error("Greenbone Bridge credentials are unavailable.");
  const response = await fetch(`${config.baseUrl}/api/v1/scans/capacity`, {
    method: "GET",
    headers: { "X-API-Key": config.apiKey, "Accept": "application/json" },
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok)
    throw new Error(`Verified Greenbone capacity unavailable (HTTP ${response.status}).`);
  const payload: unknown = await response.json();
  return validateGreenboneCapacitySnapshot(payload);
}
