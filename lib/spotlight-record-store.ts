import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { applicationDatabase } from "./persist";

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

export type SpotlightCheckpoint = {
  id: string;
  tenantKey: string;
  phase: "discovering" | "hydrating";
  queryCursor: string;
  hydrationCursor: string;
  discoveredCount: number;
  expectedCount: number | null;
  hydratedCount: number;
};

function checkpoint(row: any): SpotlightCheckpoint {
  return {
    id: String(row.id), tenantKey: String(row.tenant_key), phase: row.phase,
    queryCursor: String(row.query_cursor ?? ""),
    hydrationCursor: String(row.hydration_cursor ?? ""),
    discoveredCount: Number(row.discovered_count ?? 0),
    expectedCount: row.expected_count == null ? null : Number(row.expected_count),
    hydratedCount: Number(row.hydrated_count ?? 0),
  };
}

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
        CREATE INDEX IF NOT EXISTS spotlight_runs_tenant_status
          ON spotlight_import_runs (tenant_key, status, started_at DESC);
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS checkpoint_version INTEGER NOT NULL DEFAULT 1;
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT 'legacy';
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS query_cursor TEXT NOT NULL DEFAULT '';
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS hydration_cursor TEXT NOT NULL DEFAULT '';
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS discovered_count BIGINT NOT NULL DEFAULT 0;
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS expected_count BIGINT;
        ALTER TABLE spotlight_import_runs ADD COLUMN IF NOT EXISTS hydrated_count BIGINT NOT NULL DEFAULT 0;
        CREATE TABLE IF NOT EXISTS spotlight_import_ids (
          run_id UUID NOT NULL REFERENCES spotlight_import_runs(id),
          tenant_key TEXT NOT NULL,
          source_id TEXT NOT NULL,
          PRIMARY KEY (run_id, tenant_key, source_id)
        );
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
    await db.query(`UPDATE spotlight_import_runs SET status = 'failed',
      finished_at = now(), error = 'Interrupted by replacement run'
      WHERE tenant_key = $1 AND status = 'running'`, [tenantKey]);
    await db.query("INSERT INTO spotlight_import_runs (id, tenant_key, status) VALUES ($1::uuid, $2, 'running')", [id, tenantKey]);
    return id;
  }

  async function beginOrResumeSpotlightRun(tenantKey: string): Promise<SpotlightCheckpoint> {
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(1700, hashtext($1))", [tenantKey]);
      const existing = await client.query(`SELECT id, tenant_key, phase, query_cursor,
        hydration_cursor, discovered_count, expected_count, hydrated_count
        FROM spotlight_import_runs WHERE tenant_key = $1 AND checkpoint_version = 2
          AND status IN ('running', 'failed') AND phase IN ('discovering', 'hydrating')
        ORDER BY started_at DESC LIMIT 1 FOR UPDATE`, [tenantKey]);
      let row;
      if (existing.rows.length) {
        const resumed = await client.query(`UPDATE spotlight_import_runs
          SET status = 'running', finished_at = NULL, error = NULL
          WHERE id = $1::uuid RETURNING id, tenant_key, phase, query_cursor,
            hydration_cursor, discovered_count, expected_count, hydrated_count`, [existing.rows[0].id]);
        row = resumed.rows[0];
      } else {
        await client.query(`UPDATE spotlight_import_runs SET status = 'failed',
          finished_at = now(), error = 'Interrupted before resumable checkpoint'
          WHERE tenant_key = $1 AND status = 'running'`, [tenantKey]);
        const created = await client.query(`INSERT INTO spotlight_import_runs
          (id, tenant_key, status, checkpoint_version, phase)
          VALUES ($1::uuid, $2, 'running', 2, 'discovering')
          RETURNING id, tenant_key, phase, query_cursor, hydration_cursor,
            discovered_count, expected_count, hydrated_count`, [randomUUID(), tenantKey]);
        row = created.rows[0];
      }
      if (!row) throw new Error("Could not create or resume Spotlight import run.");
      await client.query("COMMIT");
      return checkpoint(row);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function saveSpotlightIdPage(runId: string, tenantKey: string, priorCursor: string,
    ids: string[], nextCursor: string, reportedTotal: number | null): Promise<SpotlightCheckpoint> {
    if (ids.some(id => !id?.trim())) throw new Error("Spotlight discovery returned an invalid source ID.");
    if (!ids.length && nextCursor) throw new Error("Spotlight discovery returned an empty page with a cursor.");
    if (nextCursor && nextCursor === priorCursor) throw new Error("Spotlight discovery cursor repeated.");
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT phase, query_cursor, discovered_count
        FROM spotlight_import_runs WHERE id = $1::uuid AND tenant_key = $2
          AND status = 'running' FOR UPDATE`, [runId, tenantKey]);
      if (locked.rows[0]?.phase !== "discovering" || locked.rows[0]?.query_cursor !== priorCursor)
        throw new Error("Spotlight discovery checkpoint changed during the import.");
      const seenCount = Number(locked.rows[0].discovered_count) + ids.length;
      if (!nextCursor && reportedTotal != null && seenCount < reportedTotal)
        throw new Error(`Spotlight pagination incomplete: received ${seenCount} of ${reportedTotal} IDs.`);
      if (ids.length) await client.query(`INSERT INTO spotlight_import_ids (run_id, tenant_key, source_id)
        SELECT $1::uuid, $2, value FROM jsonb_array_elements_text($3::jsonb) AS value
        ON CONFLICT (run_id, tenant_key, source_id) DO NOTHING`, [runId, tenantKey, JSON.stringify(ids)]);
      const updated = await client.query(`UPDATE spotlight_import_runs SET
        query_cursor = $3, discovered_count = $4,
        phase = CASE WHEN $3 = '' THEN 'hydrating' ELSE 'discovering' END,
        expected_count = CASE WHEN $3 = '' THEN
          (SELECT COUNT(*) FROM spotlight_import_ids WHERE run_id = $1::uuid AND tenant_key = $2)
          ELSE NULL END
        WHERE id = $1::uuid AND tenant_key = $2
        RETURNING id, tenant_key, phase, query_cursor, hydration_cursor,
          discovered_count, expected_count, hydrated_count`, [runId, tenantKey, nextCursor, seenCount]);
      await client.query("COMMIT");
      return checkpoint(updated.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function nextSpotlightHydrationIds(runId: string, tenantKey: string,
    afterId: string, limit = 3200): Promise<string[]> {
    await ensureSchema();
    const safeLimit = Math.min(3200, Math.max(1, Math.trunc(limit) || 3200));
    const result = await db.query(`SELECT source_id FROM spotlight_import_ids
      WHERE run_id = $1::uuid AND tenant_key = $2 AND source_id > $3
      ORDER BY source_id LIMIT $4`, [runId, tenantKey, afterId, safeLimit]);
    return result.rows.map(row => String(row.source_id));
  }

  async function writeSpotlightHydrationBatch(runId: string, tenantKey: string,
    ids: string[], rows: SpotlightRecord[]): Promise<number> {
    if (!ids.length) return 0;
    if (ids.some(id => !id?.trim()) || new Set(ids).size !== ids.length)
      throw new Error("Spotlight hydration IDs must be unique and nonempty.");
    const expected = new Set(ids);
    if (rows.length !== ids.length || rows.some(row =>
      !expected.has(row.sourceId) || row.tenantKey !== tenantKey || row.raw == null) ||
      new Set(rows.map(row => row.sourceId)).size !== ids.length)
      throw new Error("Spotlight hydration source IDs do not match the checkpoint batch.");
    const payload = rows.map(row => ({
      source_id: row.sourceId, company_id: row.companyId, hostname: row.hostname,
      local_ip: row.localIp, external_ip: row.externalIp, cve: row.cve,
      severity: row.severity, status: row.status, description: row.description,
      remediation: row.remediation, observed_at: row.observedAt, raw: row.raw,
    }));
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT phase, hydration_cursor,
        hydration_cursor < $3 AS advances FROM spotlight_import_runs
        WHERE id = $1::uuid AND tenant_key = $2 AND status = 'running' FOR UPDATE`, [runId, tenantKey]);
      if (locked.rows[0]?.phase !== "hydrating" || locked.rows[0]?.advances === false)
        throw new Error("Spotlight hydration checkpoint changed during the import.");
      const inserted = await client.query(`INSERT INTO spotlight_import_records
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
          observed_at = EXCLUDED.observed_at, raw = EXCLUDED.raw`,
        [runId, tenantKey, JSON.stringify(payload)]);
      if (inserted.rowCount !== ids.length) throw new Error("Spotlight hydration write count mismatch.");
      await client.query(`UPDATE spotlight_import_runs SET hydration_cursor = $3,
        hydrated_count = hydrated_count + $4 WHERE id = $1::uuid AND tenant_key = $2`,
        [runId, tenantKey, ids[ids.length - 1], ids.length]);
      await client.query("COMMIT");
      return ids.length;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function abandonSpotlightDiscovery(runId: string, tenantKey: string, reason: string): Promise<void> {
    await ensureSchema();
    await db.query(`UPDATE spotlight_import_runs SET status = 'failed', phase = 'abandoned',
      finished_at = now(), error = $3 WHERE id = $1::uuid AND tenant_key = $2
        AND phase = 'discovering' AND status = 'running'`, [runId, tenantKey, reason]);
  }

  async function completeResumableSpotlightRun(runId: string, tenantKey: string): Promise<{
    findingsImported: number; hostsAffected: number;
  }> {
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const run = await client.query(`SELECT phase, expected_count, hydrated_count
        FROM spotlight_import_runs WHERE id = $1::uuid AND tenant_key = $2
          AND status = 'running' FOR UPDATE`, [runId, tenantKey]);
      if (run.rows[0]?.phase !== "hydrating" || run.rows[0]?.expected_count == null)
        throw new Error("Spotlight run has not finished ID discovery.");
      const counts = await client.query(`SELECT
        (SELECT COUNT(*) FROM spotlight_import_ids WHERE run_id = $1::uuid AND tenant_key = $2)::text AS ids,
        COUNT(*)::text AS records,
        COUNT(DISTINCT NULLIF(hostname, ''))::text AS hosts,
        (SELECT COUNT(*) FROM spotlight_import_ids i
          WHERE i.run_id = $1::uuid AND i.tenant_key = $2
            AND NOT EXISTS (SELECT 1 FROM spotlight_import_records r
              WHERE r.run_id = i.run_id AND r.tenant_key = i.tenant_key
                AND r.source_id = i.source_id))::text AS missing,
        (SELECT COUNT(*) FROM spotlight_import_records r
          WHERE r.run_id = $1::uuid AND r.tenant_key = $2
            AND NOT EXISTS (SELECT 1 FROM spotlight_import_ids i
              WHERE i.run_id = r.run_id AND i.tenant_key = r.tenant_key
                AND i.source_id = r.source_id))::text AS extra
        FROM spotlight_import_records WHERE run_id = $1::uuid AND tenant_key = $2`, [runId, tenantKey]);
      const ids = Number(counts.rows[0]?.ids ?? 0);
      const records = Number(counts.rows[0]?.records ?? 0);
      if (ids !== Number(run.rows[0].expected_count) || records !== ids ||
          Number(run.rows[0].hydrated_count) !== ids ||
          Number(counts.rows[0]?.missing ?? 0) !== 0 || Number(counts.rows[0]?.extra ?? 0) !== 0)
        throw new Error(`Spotlight source ID count mismatch: discovered ${ids}, stored ${records}.`);
      const updated = await client.query(`UPDATE spotlight_import_runs
        SET status = 'completed', finished_at = now(), error = NULL
        WHERE id = $1::uuid AND tenant_key = $2 AND status = 'running' RETURNING id`, [runId, tenantKey]);
      if (updated.rowCount !== 1) throw new Error("Spotlight run is missing or no longer running.");
      await client.query(`INSERT INTO spotlight_import_current (tenant_key, run_id)
        VALUES ($1, $2::uuid) ON CONFLICT (tenant_key) DO UPDATE
        SET run_id = EXCLUDED.run_id, promoted_at = now()`, [tenantKey, runId]);
      await client.query("COMMIT");
      return { findingsImported: records, hostsAffected: Number(counts.rows[0]?.hosts ?? 0) };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
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

  async function completeSpotlightRun(runId: string, tenantKey: string, expectedCount: number): Promise<number> {
    await ensureSchema();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const counted = await client.query(`SELECT COUNT(*)::text AS count FROM spotlight_import_records
        WHERE run_id = $1::uuid AND tenant_key = $2`, [runId, tenantKey]);
      const recordCount = Number(counted.rows[0]?.count ?? 0);
      if (recordCount !== expectedCount) {
        throw new Error(`Spotlight source ID count mismatch: fetched ${expectedCount}, stored ${recordCount}.`);
      }
      const updated = await client.query(`UPDATE spotlight_import_runs
        SET status = 'completed', finished_at = now(), error = NULL
        WHERE id = $1::uuid AND tenant_key = $2 AND status = 'running' RETURNING id`, [runId, tenantKey]);
      if (updated.rowCount !== 1) throw new Error("Spotlight run is missing or no longer running.");
      await client.query(`INSERT INTO spotlight_import_current (tenant_key, run_id)
        VALUES ($1, $2::uuid) ON CONFLICT (tenant_key) DO UPDATE
        SET run_id = EXCLUDED.run_id, promoted_at = now()`, [tenantKey, runId]);
      await client.query("COMMIT");
      return recordCount;
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

  // Keep only the active completed generation. Delete old or interrupted runs
  // in small transactions so one cleanup query cannot monopolize Postgres.
  async function pruneSpotlightRuns(tenantKey: string): Promise<void> {
    await ensureSchema();
    const active = await db.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key = $1", [tenantKey]);
    const activeId = active.rows[0]?.run_id ?? null;
    const old = await db.query(`SELECT id FROM spotlight_import_runs
      WHERE tenant_key = $1 AND status <> 'running'
        AND ($2::uuid IS NULL OR id <> $2::uuid)`, [tenantKey, activeId]);
    for (const { id } of old.rows) {
      while (true) {
        const deleted = await db.query(`WITH doomed AS (
          SELECT r.ctid FROM spotlight_import_records r
          WHERE r.run_id = $1::uuid AND r.tenant_key = $2
            AND NOT EXISTS (SELECT 1 FROM spotlight_import_current c
              WHERE c.tenant_key = r.tenant_key AND c.run_id = r.run_id)
          LIMIT 10000
        ) DELETE FROM spotlight_import_records r USING doomed
          WHERE r.ctid = doomed.ctid`, [id, tenantKey]);
        if ((deleted.rowCount ?? 0) < 10000) break;
        await new Promise<void>(resolve => setImmediate(resolve));
      }
      while (true) {
        const deleted = await db.query(`WITH doomed AS (
          SELECT i.ctid FROM spotlight_import_ids i
          WHERE i.run_id = $1::uuid AND i.tenant_key = $2
            AND NOT EXISTS (SELECT 1 FROM spotlight_import_current c
              WHERE c.tenant_key = i.tenant_key AND c.run_id = i.run_id)
          LIMIT 10000
        ) DELETE FROM spotlight_import_ids i USING doomed WHERE i.ctid = doomed.ctid`, [id, tenantKey]);
        if ((deleted.rowCount ?? 0) < 10000) break;
        await new Promise<void>(resolve => setImmediate(resolve));
      }
      await db.query(`DELETE FROM spotlight_import_runs r WHERE r.id = $1::uuid
        AND NOT EXISTS (SELECT 1 FROM spotlight_import_current c WHERE c.run_id = r.id)`, [id]);
    }
  }

  return { beginSpotlightRun, beginOrResumeSpotlightRun, saveSpotlightIdPage,
    nextSpotlightHydrationIds, writeSpotlightHydrationBatch, abandonSpotlightDiscovery,
    completeResumableSpotlightRun, writeSpotlightBatch, completeSpotlightRun,
    failSpotlightRun, countCompletedSpotlightRecords, listCompletedSpotlightRecords,
    pruneSpotlightRuns };
}

let runtimeStore: ReturnType<typeof createSpotlightRecordStore> | undefined;
let runtimePool: Pool | undefined;

function configuredStore() {
  const db = applicationDatabase();
  if (!db) throw new Error("DATABASE_URL is required for complete Spotlight record storage.");
  if (!runtimeStore || runtimePool !== db) {
    runtimePool = db;
    runtimeStore = createSpotlightRecordStore(db);
  }
  return runtimeStore;
}

export const beginSpotlightRun = (tenantKey: string) => configuredStore().beginSpotlightRun(tenantKey);
export const beginOrResumeSpotlightRun = (tenantKey: string) => configuredStore().beginOrResumeSpotlightRun(tenantKey);
export const saveSpotlightIdPage = (runId: string, tenantKey: string, priorCursor: string,
  ids: string[], nextCursor: string, reportedTotal: number | null) =>
  configuredStore().saveSpotlightIdPage(runId, tenantKey, priorCursor, ids, nextCursor, reportedTotal);
export const nextSpotlightHydrationIds = (runId: string, tenantKey: string, afterId: string, limit?: number) =>
  configuredStore().nextSpotlightHydrationIds(runId, tenantKey, afterId, limit);
export const writeSpotlightHydrationBatch = (runId: string, tenantKey: string, ids: string[], rows: SpotlightRecord[]) =>
  configuredStore().writeSpotlightHydrationBatch(runId, tenantKey, ids, rows);
export const abandonSpotlightDiscovery = (runId: string, tenantKey: string, reason: string) =>
  configuredStore().abandonSpotlightDiscovery(runId, tenantKey, reason);
export const completeResumableSpotlightRun = (runId: string, tenantKey: string) =>
  configuredStore().completeResumableSpotlightRun(runId, tenantKey);
export const writeSpotlightBatch = (runId: string, tenantKey: string, rows: SpotlightRecord[]) =>
  configuredStore().writeSpotlightBatch(runId, tenantKey, rows);
export const completeSpotlightRun = (runId: string, tenantKey: string, expectedCount: number) =>
  configuredStore().completeSpotlightRun(runId, tenantKey, expectedCount);
export const failSpotlightRun = (runId: string, error: string) =>
  configuredStore().failSpotlightRun(runId, error);
export const countCompletedSpotlightRecords = (tenantKey: string) =>
  configuredStore().countCompletedSpotlightRecords(tenantKey);
export const listCompletedSpotlightRecords = (tenantKey: string, limit?: number, offset?: number) =>
  configuredStore().listCompletedSpotlightRecords(tenantKey, limit, offset);
export const pruneSpotlightRuns = (tenantKey: string) => configuredStore().pruneSpotlightRuns(tenantKey);
