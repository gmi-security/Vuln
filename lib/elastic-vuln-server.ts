import { createHash, timingSafeEqual } from "node:crypto";
import { Pool } from "pg";
import { parseAssetCoverage, type AssetCoverageSnapshot, type ElasticCoverageView } from "./elastic-vuln";

export function elasticVulnEnabled(): boolean {
  return process.env.ELASTIC_VULN_ENABLED === "true";
}

export function elasticIngestAuthorized(request: Request): boolean {
  const expected = (process.env.ELASTIC_VULN_INGEST_TOKEN ?? "").trim();
  const header = request.headers.get("authorization") ?? "";
  if (expected.length < 32 || !header.startsWith("Bearer ")) return false;
  const hash = (text: string) => createHash("sha256").update(text).digest();
  return timingSafeEqual(hash(header.slice(7).trim()), hash(expected));
}

let pool: Pool | undefined;
let ready: Promise<void> | undefined;

async function database(): Promise<Pool> {
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (!url) throw new Error("Elastic snapshot storage is not configured.");
  pool ??= new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30_000, statement_timeout: 5000 });
  if (!ready) {
    ready = pool.query(`CREATE TABLE IF NOT EXISTS elastic_query_snapshots (
      query_id TEXT PRIMARY KEY,
      collected_at TIMESTAMPTZ NOT NULL,
      payload JSONB NOT NULL
    )`).then(() => undefined).catch((error) => { ready = undefined; throw error; });
  }
  await ready;
  return pool;
}

export async function saveAssetCoverage(snapshot: AssetCoverageSnapshot): Promise<boolean> {
  const db = await database();
  // Older/repeated workflow runs cannot overwrite a newer snapshot.
  const result = await db.query(`INSERT INTO elastic_query_snapshots (query_id, collected_at, payload)
    VALUES ($1, $2, $3::jsonb)
    ON CONFLICT (query_id) DO UPDATE SET collected_at = EXCLUDED.collected_at, payload = EXCLUDED.payload
    WHERE elastic_query_snapshots.collected_at < EXCLUDED.collected_at
    RETURNING query_id`, [snapshot.queryId, snapshot.collectedAt, JSON.stringify(snapshot)]);
  return (result.rowCount ?? 0) > 0;
}

export async function getElasticCoverageView(): Promise<ElasticCoverageView> {
  if (process.env.ELASTIC_VULN_SAMPLE_DATA === "true") {
    return { mode: "sample", snapshot: { queryId: "asset-coverage",
      collectedAt: "2000-01-01T00:00:00.000Z",
      results: { managed: 120, unmanaged: 30, coverage_pct: 80 } } };
  }
  if (!process.env.ELASTIC_VULN_DATABASE_URL) return { mode: "unconfigured", snapshot: null };
  try {
    const db = await database();
    const result = await db.query("SELECT payload FROM elastic_query_snapshots WHERE query_id = $1", ["asset-coverage"]);
    if (!result.rows.length) return { mode: "empty", snapshot: null };
    return { mode: "live", snapshot: parseAssetCoverage(result.rows[0].payload) };
  } catch {
    // Database errors may include private connection details.
    return { mode: "unavailable", snapshot: null };
  }
}
