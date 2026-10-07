import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { applicationDatabase } from "./persist";
import { DefenderError, openDefender, sealDefender, type DefenderCredentials, type DefenderRecord } from "./defender-client";
import type { DefenderSnapshot, DefenderFinding } from "./defender-projection";

type Database = Pick<Pool, "query" | "connect">;
export type DefenderConnectionInput = DefenderCredentials & { companyId: string; daily: boolean };
export type DefenderRun = { id: string; company_id: string; revision: number; status: string; phase: string; fetched: number; skipped: number; error: string | null; started_at: string; finished_at: string | null };
export type DefenderSummary = { findings: number; cves: number; affectedDevices: number; inventoryDevices: number; severity: Record<string, number> };
export function createDefenderStore(db: Database) {
  let ready: Promise<unknown> | undefined;
  function schema() {
    return ready ??= db.query(`
      CREATE TABLE IF NOT EXISTS defender_connections (
        company_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE, client_id TEXT NOT NULL,
        secret TEXT NOT NULL, revision INT NOT NULL DEFAULT 1, daily BOOLEAN NOT NULL DEFAULT false,
        current_run UUID, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_by TEXT NOT NULL,
        last_attempt_at TIMESTAMPTZ, last_success_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS defender_import_runs (
        id UUID PRIMARY KEY, company_id TEXT NOT NULL REFERENCES defender_connections(company_id), revision INT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('queued','running','succeeded','failed')),
        phase TEXT NOT NULL DEFAULT 'Queued', fetched INT NOT NULL DEFAULT 0, skipped INT NOT NULL DEFAULT 0,
        summary JSONB, error TEXT, actor TEXT NOT NULL, started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at TIMESTAMPTZ, lease_until TIMESTAMPTZ
      );
      CREATE UNIQUE INDEX IF NOT EXISTS defender_active_run ON defender_import_runs(company_id) WHERE status IN ('queued','running');
      CREATE INDEX IF NOT EXISTS defender_runs_company ON defender_import_runs(company_id, started_at DESC);
      CREATE TABLE IF NOT EXISTS defender_records (
        run_id UUID NOT NULL REFERENCES defender_import_runs(id) ON DELETE CASCADE,
        source_id TEXT NOT NULL, device_id TEXT NOT NULL, cve TEXT NOT NULL, severity TEXT NOT NULL,
        cvss DOUBLE PRECISION, record JSONB NOT NULL, PRIMARY KEY(run_id, source_id)
      );
      CREATE INDEX IF NOT EXISTS defender_records_cve ON defender_records(run_id,cve,device_id);
      CREATE INDEX IF NOT EXISTS defender_records_device ON defender_records(run_id,device_id);
      CREATE TABLE IF NOT EXISTS defender_devices (
        run_id UUID NOT NULL REFERENCES defender_import_runs(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL, record JSONB NOT NULL, PRIMARY KEY(run_id,device_id)
      );
      CREATE TABLE IF NOT EXISTS defender_cves (
        run_id UUID NOT NULL REFERENCES defender_import_runs(id) ON DELETE CASCADE,
        cve TEXT NOT NULL, severity TEXT NOT NULL, severity_rank INT NOT NULL,
        cvss DOUBLE PRECISION, devices INT NOT NULL, findings INT NOT NULL, PRIMARY KEY(run_id,cve)
      );
      CREATE INDEX IF NOT EXISTS defender_cves_order ON defender_cves(run_id,severity_rank DESC,devices DESC,cve);
      CREATE TABLE IF NOT EXISTS defender_daily_history (
        company_id TEXT NOT NULL REFERENCES defender_connections(company_id), day DATE NOT NULL,
        summary JSONB NOT NULL, observed_at TIMESTAMPTZ NOT NULL, PRIMARY KEY(company_id,day)
      );
    `).catch(error => { ready = undefined; throw error; });
  }
  async function transaction<T>(action: (client: PoolClient) => Promise<T>): Promise<T> {
    await schema();
    const client = await db.connect();
    try { await client.query("BEGIN"); const result = await action(client); await client.query("COMMIT"); return result; }
    catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
    finally { client.release(); }
  }
  async function connection(companyId: string) {
    await schema();
    return (await db.query("SELECT * FROM defender_connections WHERE company_id=$1", [companyId])).rows[0];
  }
  async function credentials(companyId: string, draft?: Partial<DefenderCredentials>): Promise<DefenderCredentials> {
    const saved = await connection(companyId);
    const previous = saved ? openDefender(saved.secret) : undefined;
    if (previous && !draft?.clientSecret &&
      ((draft?.tenantId && draft.tenantId.toLowerCase() !== previous.tenantId) || (draft?.clientId && draft.clientId.toLowerCase() !== previous.clientId))) {
      throw new DefenderError("Enter the client secret again when changing tenant or application ID.");
    }
    return { tenantId: draft?.tenantId?.trim() || previous?.tenantId || "", clientId: draft?.clientId?.trim() || previous?.clientId || "",
      clientSecret: draft?.clientSecret || previous?.clientSecret || "" };
  }
  async function save(input: DefenderConnectionInput, actor: string) {
    const sealed = sealDefender(input);
    return transaction(async client => {
      // Serialize edits, imports and scheduling for this customer's connection.
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 804230))", [input.companyId]);
      const existing = (await client.query("SELECT * FROM defender_connections WHERE company_id=$1 FOR UPDATE", [input.companyId])).rows[0];
      const busy = await client.query("SELECT id FROM defender_import_runs WHERE company_id=$1 AND status IN ('queued','running')", [input.companyId]);
      if (busy.rowCount) throw new DefenderError("Wait for this customer's import to finish before editing the connection.", 409);
      if (existing?.current_run && existing.tenant_id !== input.tenantId.toLowerCase()) throw new DefenderError("This customer already has imported data from another tenant. A tenant migration must be handled separately.", 409);
      await client.query(`INSERT INTO defender_connections(company_id,tenant_id,client_id,secret,daily,updated_by)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(company_id) DO UPDATE SET
        tenant_id=EXCLUDED.tenant_id,client_id=EXCLUDED.client_id,secret=EXCLUDED.secret,daily=EXCLUDED.daily,
        revision=defender_connections.revision+1,updated_at=now(),updated_by=EXCLUDED.updated_by`,
        [input.companyId, input.tenantId.toLowerCase(), input.clientId.toLowerCase(), sealed, input.daily, actor]);
    });
  }
  async function list(companyId?: string) {
    await schema();
    return (await db.query(`SELECT c.company_id AS "companyId", c.tenant_id AS "tenantId", c.client_id AS "clientId", c.daily,
      c.last_success_at AS "lastSuccessAt", c.current_run AS "currentRun", c.revision,
      true AS "hasSecret", latest.status, latest.phase, latest.fetched, latest.skipped, latest.error,
      latest.started_at AS "startedAt", latest.finished_at AS "finishedAt"
      FROM defender_connections c LEFT JOIN LATERAL (
        SELECT * FROM defender_import_runs r WHERE r.company_id=c.company_id ORDER BY started_at DESC LIMIT 1
      ) latest ON true WHERE ($1::text IS NULL OR c.company_id=$1) ORDER BY c.company_id`, [companyId ?? null])).rows;
  }
  async function enqueue(companyId: string, actor: string) {
    return transaction(async client => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 804230))", [companyId]);
      const saved = (await client.query("SELECT revision,daily,last_attempt_at,current_run FROM defender_connections WHERE company_id=$1 FOR UPDATE", [companyId])).rows[0];
      if (!saved) throw new DefenderError("Save this customer's Defender connection first.");
      if (actor === "daily-scheduler" && (!saved.daily || !saved.current_run || new Date(saved.last_attempt_at).getTime() > Date.now()-86_400_000)) return null;
      const existing = (await client.query("SELECT id FROM defender_import_runs WHERE company_id=$1 AND status IN ('queued','running')", [companyId])).rows[0];
      if (existing) return String(existing.id);
      const id = randomUUID();
      await client.query("INSERT INTO defender_import_runs(id,company_id,revision,status,actor) VALUES($1,$2,$3,'queued',$4)", [id,companyId,saved.revision,actor]);
      await client.query("UPDATE defender_connections SET last_attempt_at=now() WHERE company_id=$1", [companyId]);
      return id;
    });
  }
  async function claim(): Promise<DefenderRun | null> {
    return transaction(async client => {
      // One Defender import at a time across all web processes, without a connection held during network requests.
      await client.query("SELECT pg_advisory_xact_lock(804231)");
      await client.query(`UPDATE defender_import_runs SET status='failed', phase='Interrupted',
        error='The import worker stopped before completion. Retry Sync now; previous results are retained.', finished_at=now()
        WHERE status='running' AND lease_until < now()`);
      if ((await client.query("SELECT 1 FROM defender_import_runs WHERE status='running' LIMIT 1")).rowCount) return null;
      const row = (await client.query(`UPDATE defender_import_runs SET status='running',phase='Devices',lease_until=now()+interval '10 minutes'
        WHERE id=(SELECT id FROM defender_import_runs WHERE status='queued' ORDER BY started_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *`)).rows[0];
      return row ?? null;
    });
  }
  async function assertLease(client: Pick<PoolClient,"query">, id: string) {
    const result = await client.query(`UPDATE defender_import_runs SET lease_until=now()+interval '10 minutes'
      WHERE id=$1 AND status='running' AND lease_until>now() RETURNING id`, [id]);
    if (result.rowCount !== 1) throw new DefenderError("Import lease expired. Previous completed results are retained.", 409);
  }
  async function writeDevices(id: string, rows: Record<string, unknown>[]) {
    const payload = rows.map(v => {
      if (typeof v.id !== "string" || !v.id) throw new DefenderError("Defender returned a device without an ID. Import was not published.");
      return { device_id: v.id, record: { deviceId: v.id, hostname: String(v.computerDnsName || v.id), os: String(v.osPlatform ?? ""), ip: String(v.lastIpAddress ?? ""), lastSeen: v.lastSeen ?? null } };
    });
    await transaction(async client => {
      await assertLease(client,id);
      await client.query(`INSERT INTO defender_devices(run_id,device_id,record)
        SELECT $1,v.device_id,v.record FROM jsonb_to_recordset($2::jsonb) v(device_id TEXT,record JSONB)
        ON CONFLICT(run_id,device_id) DO UPDATE SET record=EXCLUDED.record`, [id,JSON.stringify([...new Map(payload.map(v=>[v.device_id,v])).values()])]);
    });
  }
  async function writeRecords(id: string, rows: DefenderRecord[], fetched: number, skipped: number) {
    await transaction(async client => {
      await assertLease(client,id);
      await client.query(`INSERT INTO defender_records(run_id,source_id,device_id,cve,severity,cvss,record)
        SELECT $1,v.source_id,v.device_id,v.cve,v.severity,v.cvss,v.record FROM jsonb_to_recordset($2::jsonb)
        v(source_id TEXT,device_id TEXT,cve TEXT,severity TEXT,cvss DOUBLE PRECISION,record JSONB)
        ON CONFLICT(run_id,source_id) DO UPDATE SET severity=EXCLUDED.severity,cvss=EXCLUDED.cvss,record=EXCLUDED.record`,
        [id,JSON.stringify([...new Map(rows.map(v=>[v.sourceId,{ source_id:v.sourceId,device_id:v.deviceId,cve:v.cve,severity:v.severity,cvss:v.cvss,record:v }])).values()])]);
      await client.query("UPDATE defender_import_runs SET phase='Vulnerabilities',fetched=fetched+$2,skipped=skipped+$3 WHERE id=$1", [id,fetched,skipped]);
    });
  }
  async function finish(run: DefenderRun) {
    return transaction(async client => {
      await assertLease(client,run.id);
      const saved = (await client.query("SELECT revision FROM defender_connections WHERE company_id=$1 FOR UPDATE", [run.company_id])).rows[0];
      if (saved?.revision !== run.revision) throw new DefenderError("Connection changed while importing; results were not published.",409);
      await client.query(`INSERT INTO defender_cves(run_id,cve,severity,severity_rank,cvss,devices,findings)
        SELECT $1,cve,(ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[MAX(CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END)],
        MAX(CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END),MAX(cvss),COUNT(DISTINCT device_id),COUNT(*)
        FROM defender_records WHERE run_id=$1 GROUP BY cve`, [run.id]);
      const counts = (await client.query(`SELECT COUNT(*)::int AS findings,COUNT(DISTINCT cve)::int AS cves,COUNT(DISTINCT device_id)::int AS "affectedDevices" FROM defender_records WHERE run_id=$1`, [run.id])).rows[0];
      const devices = (await client.query("SELECT COUNT(*)::int AS count FROM defender_devices WHERE run_id=$1", [run.id])).rows[0];
      const severity = (await client.query("SELECT severity,COUNT(*)::int AS count FROM defender_records WHERE run_id=$1 GROUP BY severity", [run.id])).rows;
      const summary: DefenderSummary = { ...counts, inventoryDevices:devices.count, severity:Object.fromEntries(severity.map(r=>[r.severity,r.count])) };
      await client.query("UPDATE defender_import_runs SET status='succeeded',phase='Complete',summary=$2::jsonb,finished_at=now(),lease_until=NULL WHERE id=$1", [run.id,JSON.stringify(summary)]);
      await client.query("UPDATE defender_connections SET current_run=$2,last_success_at=now() WHERE company_id=$1", [run.company_id,run.id]);
      await client.query(`INSERT INTO defender_daily_history(company_id,day,summary,observed_at) VALUES($1,(now() AT TIME ZONE 'UTC')::date,$2::jsonb,now())
        ON CONFLICT(company_id,day) DO UPDATE SET summary=EXCLUDED.summary,observed_at=EXCLUDED.observed_at`, [run.company_id,JSON.stringify(summary)]);
      return summary;
    });
  }
  async function fail(id: string, message: string) {
    await schema();
    await db.query("UPDATE defender_import_runs SET status='failed',phase='Failed',error=$2,finished_at=now(),lease_until=NULL WHERE id=$1 AND status='running'", [id,message]);
  }
  async function schedule() {
    await schema();
    // First import is manual. Daily retries are bounded to one attempt per day.
    const due = (await db.query(`SELECT company_id FROM defender_connections WHERE daily AND current_run IS NOT NULL
      AND last_attempt_at < now()-interval '24 hours' ORDER BY last_attempt_at`)).rows;
    for (const row of due) await enqueue(row.company_id,"daily-scheduler");
  }
  async function results(companyId: string, view: string, offset: number, cve = "") {
    await schema();
    return transaction(async client => {
      // Pin one generation across totals, rows and summaries while a new import publishes.
      const saved = (await client.query(`SELECT c.current_run,r.summary,c.last_success_at FROM defender_connections c
        LEFT JOIN defender_import_runs r ON r.id=c.current_run WHERE c.company_id=$1 FOR SHARE OF c`, [companyId])).rows[0];
      if (!saved?.current_run) return { runId:null, configured:Boolean(saved), summary:null, rows:[], total:0, history:[], updatedAt:null };
      const id = saved.current_run;
      let rows, total;
      if (view === "devices") {
        rows = (await client.query(`SELECT d.record,COALESCE(f.findings,0) AS findings FROM defender_devices d LEFT JOIN LATERAL
          (SELECT COUNT(*)::int AS findings FROM defender_records r WHERE r.run_id=d.run_id AND r.device_id=d.device_id) f ON true
          WHERE d.run_id=$1 ORDER BY d.device_id LIMIT 50 OFFSET $2`, [id,offset])).rows;
        total = saved.summary.inventoryDevices;
      } else if (view === "findings") {
        rows = (await client.query("SELECT record FROM defender_records WHERE run_id=$1 AND ($3='' OR cve=$3) ORDER BY source_id LIMIT 50 OFFSET $2", [id,offset,cve])).rows;
        total = cve ? (await client.query("SELECT COUNT(*)::int AS count FROM defender_records WHERE run_id=$1 AND cve=$2",[id,cve])).rows[0].count : saved.summary.findings;
      } else {
        rows = (await client.query("SELECT cve,severity,cvss,devices,findings FROM defender_cves WHERE run_id=$1 ORDER BY severity_rank DESC,devices DESC,cve LIMIT 50 OFFSET $2",[id,offset])).rows;
        total = saved.summary.cves;
      }
      const history = (await client.query("SELECT day::text,summary,observed_at FROM defender_daily_history WHERE company_id=$1 ORDER BY day DESC LIMIT 90", [companyId])).rows.reverse();
      return { runId:id, configured:true, summary:saved.summary as DefenderSummary, rows, total, history, updatedAt:saved.last_success_at };
    });
  }
  async function prune(companyId: string) {
    await schema();
    // Retain current + previous successful run; clean failed/old batches without one giant deletion.
    const old = (await db.query(`SELECT id FROM defender_import_runs WHERE company_id=$1 AND status IN ('failed','succeeded')
      AND id NOT IN(SELECT current_run FROM defender_connections WHERE company_id=$1 AND current_run IS NOT NULL)
      AND id NOT IN(SELECT id FROM defender_import_runs WHERE company_id=$1 AND status='succeeded' ORDER BY started_at DESC LIMIT 2)
      AND started_at < now()-interval '1 day'`, [companyId])).rows;
    for (const row of old) {
      for (const table of ["defender_records","defender_devices","defender_cves"]) {
        let count;
        do { const result = await db.query(`DELETE FROM ${table} WHERE ctid IN(SELECT ctid FROM ${table} WHERE run_id=$1 LIMIT 2000)`, [row.id]); count = result.rowCount ?? 0; } while (count === 2000);
      }
      await db.query("DELETE FROM defender_import_runs WHERE id=$1",[row.id]);
    }
    await db.query("DELETE FROM defender_daily_history WHERE company_id=$1 AND day < CURRENT_DATE-365",[companyId]);
  }
  async function platformSnapshot(companyId: string): Promise<DefenderSnapshot | null> {
    return transaction(async client => {
      // Publication/pruning cannot replace this generation until our bounded
      // reads complete. No network requests or risk scoring inside this lock.
      const saved = (await client.query(`SELECT c.current_run,c.last_success_at FROM defender_connections c
        WHERE company_id=$1 FOR SHARE`,[companyId])).rows[0];
      if (!saved?.current_run) return null;
      const devices = (await client.query("SELECT record FROM defender_devices WHERE run_id=$1 ORDER BY device_id",[saved.current_run])).rows.map(r=>r.record);
      const findings: DefenderFinding[] = [];
      let afterDevice = "", afterCve = "";
      for (;;) {
        const page = (await client.query(`SELECT device_id AS "deviceId",cve,MAX(record->>'hostname') AS hostname,
          (ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[MAX(CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END)] AS severity,
          MAX(cvss) AS cvss,MIN(record->>'firstSeen') AS "firstSeen",MAX(record->>'lastSeen') AS "lastSeen",
          BOOL_OR(record->>'exploitability' IN ('ExploitIsPublic','ExploitIsVerified','ExploitIsInKit')) AS "exploitAvailable",
          STRING_AGG(DISTINCT CONCAT_WS(' · ',NULLIF(record->>'softwareName',''),NULLIF(record->>'softwareVersion',''),record->>'remediation',NULLIF(record->>'remediationId','')), E'\n') AS remediation
          FROM defender_records WHERE run_id=$1 AND (device_id,cve)>($2,$3)
          GROUP BY device_id,cve ORDER BY device_id,cve LIMIT 2000`,[saved.current_run,afterDevice,afterCve])).rows as DefenderFinding[];
        findings.push(...page);
        if (page.length < 2000) break;
        afterDevice = page[page.length-1].deviceId; afterCve = page[page.length-1].cve;
      }
      return { companyId,runId:saved.current_run,observedAt:new Date(saved.last_success_at).toISOString(),devices,findings };
    });
  }
  return { schema, credentials, connection, save, list, enqueue, claim, writeDevices, writeRecords, finish, fail, schedule, results, prune, platformSnapshot };
}
let cached: { db: Pool; store: ReturnType<typeof createDefenderStore> } | undefined;
export function defenderStore() {
  const db = applicationDatabase();
  if (!db) throw new DefenderError("DATABASE_URL is required for Defender ingestion.",503);
  if (!cached || cached.db !== db) cached = { db,store:createDefenderStore(db) };
  return cached.store;
}
