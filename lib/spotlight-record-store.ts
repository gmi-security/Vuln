import { randomUUID } from "node:crypto";
import { Pool } from "pg";

// Spotlight source records are deliberately separate from the snapshot-backed
// scanner store. A run becomes visible only when its completed pointer moves.
export type SpotlightRecord = {
  sourceId: string;
  tenantKey: string;
  companyId: string;
  hostname: string;
  localIp: string;
  externalIp: string;
  cve: string;
  severity: string;
  status: string;
  description: string;
  remediation: string;
  observedAt: string;
  raw: unknown;
};

type Database = Pick<Pool, "query" | "connect">;

export function createSpotlightRecordStore(db: Database) {
  let schemaReady: Promise<void> | undefined;
  function ensureSchema(): Promise<void> {
    if (!schemaReady) {
      schemaReady = db.query(`
        CREATE TABLE IF NOT EXISTS spotlight_import_runs (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
          started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          finished_at TIMESTAMPTZ,
          error TEXT
        );
        CREATE TABLE IF NOT EXISTS spotlight_import_current (
          tenant_key TEXT PRIMARY KEY,
          run_id UUID NOT NULL REFERENCES spotlight_import_runs(id),
          promoted_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS spotlight_import_records (
          run_id UUID NOT NULL REFERENCES spotlight_import_runs(id),
          tenant_key TEXT NOT NULL,
          source_id TEXT NOT NULL,
          company_id TEXT NOT NULL,
          hostname TEXT NOT NULL,
          local_ip TEXT NOT NULL,
          external_ip TEXT NOT NULL,
          cve TEXT NOT NULL,
          severity TEXT NOT NULL,
          status TEXT NOT NULL,
          description TEXT NOT NULL,
          remediation TEXT NOT NULL,
          observed_at TIMESTAMPTZ NOT NULL,
          raw JSONB NOT NULL,
          PRIMARY KEY (run_id, tenant_key, source_id)
        );
        CREATE INDEX IF NOT EXISTS spotlight_records_company_cve_host
          ON spotlight_import_records (company_id, cve, hostname);
        CREATE INDEX IF NOT EXISTS spotlight_runs_tenant_status
          ON spotlight_import_runs (tenant_key, status, started_at DESC);
      `).then(() => undefined).catch(error => {
        schemaReady = undefined;
        throw error;
      });
    }
    return schemaReady;
  }

  async function beginSpotlightRun(tenantKey: string): Promise<string> {
    await ensureSchema();
    const id = randomUUID();
    await db.query("INSERT INTO spotlight_import_runs (id, tenant_key, status) VALUES ($1::uuid, $2, 'running')", [id, tenantKey]);
    return id;
  }

  async function writeSpotlightBatch(runId: string, tenantKey: string, rows: SpotlightRecord[]): Promise<number> {
    if (!rows.length) return 0;
    const distinct = new Map<string, SpotlightRecord>();
    for (const row of rows) {
      if (!row.sourceId?.trim()) throw new Error("Spotlight source ID is required for every record.");
      if (row.tenantKey !== tenantKey) throw new Error("Spotlight record tenant does not match the run.");
      if (row.raw === undefined || row.raw === null) throw new Error("Spotlight raw source payload is required.");
      distinct.set(row.sourceId, row);
    }
    await ensureSchema();
    const payload = [...distinct.values()].map(row => ({
      source_id: row.sourceId, company_id: row.companyId, hostname: row.hostname,
      local_ip: row.localIp, external_ip: row.externalIp, cve: row.cve,
      severity: row.severity, status: row.status, description: row.description,
      remediation: row.remediation, observed_at: row.observedAt, raw: row.raw,
    }));
    const result = await db.query(`
      INSERT INTO spotlight_import_records
        (run_id, tenant_key, source_id, company_id, hostname, local_ip, external_ip,
         cve, severity, status, description, remediation, observed_at, raw)
      SELECT $1::uuid, $2, r.source_id, r.company_id, r.hostname, r.local_ip, r.external_ip,
             r.cve, r.severity, r.status, r.description, r.remediation, r.observed_at, r.raw
      FROM jsonb_to_recordset($3::jsonb) AS r(
        source_id TEXT, company_id TEXT, hostname TEXT, local_ip TEXT, external_ip TEXT,
        cve TEXT, severity TEXT, status TEXT, description TEXT, remediation TEXT,
        observed_at TIMESTAMPTZ, raw JSONB)
      ON CONFLICT (run_id, tenant_key, source_id) DO UPDATE SET
        company_id = EXCLUDED.company_id, hostname = EXCLUDED.hostname,
        local_ip = EXCLUDED.local_ip, external_ip = EXCLUDED.external_ip,
        cve = EXCLUDED.cve, severity = EXCLUDED.severity, status = EXCLUDED.status,
        description = EXCLUDED.description, remediation = EXCLUDED.remediation,
        observed_at = EXCLUDED.observed_at, raw = EXCLUDED.raw
    `, [runId, tenantKey, JSON.stringify(payload)]);
    return result.rowCount ?? distinct.size;
  }

  async function completeSpotlightRun(runId: string, tenantKey: string): Promise<void> {
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(`UPDATE spotlight_import_runs
        SET status = 'completed', finished_at = now(), error = NULL
        WHERE id = $1::uuid AND tenant_key = $2 AND status = 'running' RETURNING id`, [runId, tenantKey]);
      if (updated.rowCount !== 1) throw new Error("Spotlight run is missing or no longer running.");
      await client.query(`INSERT INTO spotlight_import_current (tenant_key, run_id)
        VALUES ($1, $2::uuid) ON CONFLICT (tenant_key) DO UPDATE
        SET run_id = EXCLUDED.run_id, promoted_at = now()`, [tenantKey, runId]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function failSpotlightRun(runId: string, error: string): Promise<void> {
    await ensureSchema();
    await db.query(`UPDATE spotlight_import_runs SET status = 'failed',
      finished_at = now(), error = $2 WHERE id = $1::uuid AND status = 'running'`, [runId, error]);
  }

  async function countCompletedSpotlightRecords(tenantKey: string): Promise<number> {
    await ensureSchema();
    const result = await db.query(`SELECT COUNT(*)::text AS count FROM spotlight_import_records r
      JOIN spotlight_import_current c ON c.tenant_key = r.tenant_key AND c.run_id = r.run_id
      WHERE r.tenant_key = $1`, [tenantKey]);
    return Number(result.rows[0]?.count ?? 0);
  }

  async function listCompletedSpotlightRecords(tenantKey: string, limit = 100, offset = 0): Promise<SpotlightRecord[]> {
    await ensureSchema();
    const safeLimit = Math.min(1000, Math.max(1, Math.trunc(limit) || 100));
    const safeOffset = Math.max(0, Math.trunc(offset) || 0);
    const result = await db.query(`SELECT r.source_id, r.tenant_key, r.company_id, r.hostname,
      r.local_ip, r.external_ip, r.cve, r.severity, r.status, r.description,
      r.remediation, r.observed_at, r.raw FROM spotlight_import_records r
      JOIN spotlight_import_current c ON c.tenant_key = r.tenant_key AND c.run_id = r.run_id
      WHERE r.tenant_key = $1 ORDER BY r.source_id LIMIT $2 OFFSET $3`, [tenantKey, safeLimit, safeOffset]);
    return result.rows.map(row => ({
      sourceId: row.source_id, tenantKey: row.tenant_key, companyId: row.company_id,
      hostname: row.hostname, localIp: row.local_ip, externalIp: row.external_ip,
      cve: row.cve, severity: row.severity, status: row.status,
      description: row.description, remediation: row.remediation,
      observedAt: new Date(row.observed_at).toISOString(), raw: row.raw,
    }));
  }

  return { beginSpotlightRun, writeSpotlightBatch, completeSpotlightRun,
    failSpotlightRun, countCompletedSpotlightRecords, listCompletedSpotlightRecords };
}

let pool: Pool | undefined;
let runtimeStore: ReturnType<typeof createSpotlightRecordStore> | undefined;

function configuredStore() {
  if (runtimeStore) return runtimeStore;
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (!url) throw new Error("ELASTIC_VULN_DATABASE_URL is required for complete Spotlight record storage.");
  pool = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30_000, statement_timeout: 30_000 });
  pool.on("error", error => { console.error("[spotlight] database pool error:", error); });
  runtimeStore = createSpotlightRecordStore(pool);
  return runtimeStore;
}

export const beginSpotlightRun = (tenantKey: string) => configuredStore().beginSpotlightRun(tenantKey);
export const writeSpotlightBatch = (runId: string, tenantKey: string, rows: SpotlightRecord[]) =>
  configuredStore().writeSpotlightBatch(runId, tenantKey, rows);
export const completeSpotlightRun = (runId: string, tenantKey: string) =>
  configuredStore().completeSpotlightRun(runId, tenantKey);
export const failSpotlightRun = (runId: string, error: string) =>
  configuredStore().failSpotlightRun(runId, error);
export const countCompletedSpotlightRecords = (tenantKey: string) =>
  configuredStore().countCompletedSpotlightRecords(tenantKey);
export const listCompletedSpotlightRecords = (tenantKey: string, limit?: number, offset?: number) =>
  configuredStore().listCompletedSpotlightRecords(tenantKey, limit, offset);
