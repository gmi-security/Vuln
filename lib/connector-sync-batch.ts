import type { Pool } from "pg";
import { patchTicketDatabase } from "./patch-ticket-store";
import { connectorSyncStart } from "./connector-sync-schedule";
import { connectorImportWarnings } from "./connector-import-result";

export type SyncAllEntry = { connector: string; configured: boolean; ok: boolean; result?: unknown; error?: string };
export type ConnectorSyncJob = { connector: string; ready: boolean; getScope?: () => Promise<string>; run: (scope?: string) => Promise<unknown>; recover?: (startedAt: number, scope?: string) => Promise<unknown> };
type Entry = { connector: string; startedAt: number; scope?: string; result?: SyncAllEntry };
export class ConnectorSyncDeferredError extends Error {}
type Progress = { version: 1; nextStartAt: number; entries: Entry[] };
export type ScheduledConnectorBatch = {
  startedAt: string;
  progress: Progress | null;
  save: (progress: Progress, finished?: boolean) => Promise<void>;
  release: () => Promise<void>;
};

const jobName = "connector-sync-all";
const staggerMs = 25 * 60_000;

function readProgress(value: unknown): Progress | null {
  if (value === null) return null; // Pre-checkpoint releases recorded only the daily claim.
  const p = value as Progress;
  if (!p || p.version !== 1 || !Number.isFinite(p.nextStartAt) || !Array.isArray(p.entries) ||
      p.entries.some(e => !e || typeof e.connector !== "string" || !Number.isFinite(e.startedAt) ||
        (e.scope !== undefined && typeof e.scope !== "string") ||
        (e.result !== undefined && (!e.result || e.result.connector !== e.connector ||
          typeof e.result.configured !== "boolean" || typeof e.result.ok !== "boolean"))) ||
      new Set(p.entries.map(e => e.connector)).size !== p.entries.length)
    throw new Error("Invalid saved connector progress; automatic replay withheld.");
  return p;
}

// The session lock dies with the worker; the per-connector journal survives it.
export async function acquireScheduledConnectorBatch(
  db?: Pool, now = Date.now(),
): Promise<ScheduledConnectorBatch | null> {
  db ??= await patchTicketDatabase();
  const client = await db.connect();
  let lost = false, released = false;
  const onError = () => { lost = true; };
  client.on("error", onError);
  const release = async () => {
    if (released) return;
    released = true;
    if (!lost) {
      try { await client.query("SELECT pg_advisory_unlock(1713, 0)"); }
      catch { lost = true; }
    }
    client.off("error", onError);
    client.release(lost);
  };
  try {
    const lock = await client.query("SELECT pg_try_advisory_lock(1713, 0) AS locked");
    if (!lock.rows[0]?.locked) { await release(); return null; }
    let row = (await client.query("SELECT status,result,started_at::text AS started_at FROM background_job_runs WHERE job=$1", [jobName])).rows[0];
    if (row?.status !== "running") {
      const start = connectorSyncStart(now);
      if (start === null || (row && new Date(row.started_at).getTime() >= start)) { await release(); return null; }
      const progress: Progress = { version: 1, nextStartAt: now, entries: [] };
      row = (await client.query(`INSERT INTO background_job_runs(job,status,result,error,started_at,finished_at)
        VALUES($1,'running',$2::jsonb,NULL,$3,NULL)
        ON CONFLICT(job) DO UPDATE SET status='running',result=EXCLUDED.result,error=NULL,started_at=EXCLUDED.started_at,finished_at=NULL
        RETURNING status,result,started_at::text AS started_at`, [jobName, JSON.stringify(progress), new Date(now)])).rows[0];
    }
    const startedAt = new Date(row.started_at).toISOString();
    const progress = readProgress(row.result);
    return { startedAt, progress, release, save: async (next, finished = false) => {
      if (lost || released) throw new Error("Connector batch lost its database lock; recovery will resume it.");
      readProgress(next);
      const failed = next.entries.some(e => !e.result || (e.result.configured && !e.result.ok));
      const saved = await client.query(`UPDATE background_job_runs SET result=$2::jsonb,status=$3,error=$4,
        finished_at=CASE WHEN $5 THEN now() ELSE NULL END WHERE job=$1 AND started_at=$6 AND status='running'`,
      [jobName, JSON.stringify(next), finished ? (failed ? "failed" : "succeeded") : "running",
        finished && failed ? "One or more connector starts/imports failed or were interrupted; inspect connector sync status." : null,
        finished, row.started_at]);
      if (saved.rowCount !== 1) throw new Error("Connector batch ownership changed; automatic work stopped.");
    } };
  } catch (error) { await release(); throw error; }
}

export async function runConnectorSyncJobs(jobs: ConnectorSyncJob[], batch?: ScheduledConnectorBatch): Promise<SyncAllEntry[]> {
  const legacy = batch?.progress === null;
  const progress: Progress = batch?.progress ?? { version: 1, nextStartAt: 0, entries: [] };
  // Old batches cannot prove which scanner actions ran. Only checkpoint-aware providers can recover.
  if (legacy) {
    for (const job of jobs) progress.entries.push({ connector: job.connector, startedAt: Date.parse(batch!.startedAt),
      ...(!job.recover ? { result: { connector: job.connector, configured: job.ready, ok: false,
        ...(job.ready ? { error: "Interrupted legacy batch; prior action outcome unknown, automatic replay withheld." } : {}) } } : {}) });
    progress.nextStartAt = Date.parse(batch!.startedAt) + 2 * staggerMs;
    await batch!.save(progress);
  }
  const out: SyncAllEntry[] = [];
  for (const job of jobs) {
    let entry = progress.entries.find(e => e.connector === job.connector);
    if (entry?.result) { out.push(entry.result); continue; }
    let result: SyncAllEntry = { connector: job.connector, configured: job.ready, ok: false };
    if (job.ready) {
      const recovering = !!entry;
      const delay = progress.nextStartAt - Date.now();
      if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay));
      entry ??= { connector: job.connector, startedAt: Date.now() };
      if (!recovering) progress.entries.push(entry);
      let scopeError: string | undefined;
      try {
        const scope = await job.getScope?.();
        if (entry.scope !== undefined && entry.scope !== scope) throw new Error("Connector customer scope changed; automatic recovery withheld.");
        entry.scope ??= scope;
      } catch (error) { scopeError = error instanceof Error ? error.message : "Connector scope could not be verified."; }
      // Persist before contacting a provider, including after a connection-loss recovery.
      await batch?.save(progress);
      try {
        if (scopeError) throw new Error(scopeError);
        if (recovering && !job.recover) throw new Error("Connector was interrupted; inspect its previous action before retrying manually.");
        const r = await (recovering ? job.recover!(entry.startedAt, entry.scope) : job.run(entry.scope));
        if (r && typeof r === "object" && "error" in r) result.error = String(r.error);
        else {
          const warnings = connectorImportWarnings(r);
          result = { ...result, ok: warnings.length === 0, result: r,
            ...(warnings.length ? { error: `Import needs attention: ${warnings.join("; ")}. Successful results were retained.` } : {}) };
        }
      } catch (error) {
        if (error instanceof ConnectorSyncDeferredError) throw error;
        result.error = error instanceof Error ? error.message : "Sync failed.";
      }
      progress.nextStartAt = Date.now() + staggerMs;
    } else if (!entry) {
      entry = { connector: job.connector, startedAt: Date.now() };
      progress.entries.push(entry);
    }
    // Provider payloads can be large; the journal only needs the launch outcome.
    const { result: payload, ...summary } = result;
    entry!.result = summary;
    await batch?.save(progress);
    out.push(result);
  }
  await batch?.save(progress, true);
  return out;
}
