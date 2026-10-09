import type { Pool, PoolClient } from "pg";
import { importFreshness, validateSourceRead, type CustomerSourceRead, type CustomerSourceReadRequest, type SourceCveRow } from "./customer-source-read-model";
import { createSpotlightSummaryAccumulator, SPOTLIGHT_SUMMARY_VERSION as VERSION, spotlightSummaryDefinition,
  summaryCount, summaryLimits, validateSpotlightSummary, type SpotlightSummary, type SummaryInput } from "./spotlight-summary-model";

type Database = Pick<Pool, "connect">;
const LOCK = 804244;
function iso(value: Date | string) { return new Date(value).toISOString(); }
async function beginRead(client: PoolClient) {
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await client.query("SET LOCAL statement_timeout='15s'");
  await client.query("SET LOCAL lock_timeout='2s'");
  await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
}
async function metadata(client: PoolClient, companyId: string) {
  return (await client.query(`SELECT c.run_id,r.id AS owned_run,r.status,r.finished_at,r.checkpoint_version,r.expected_count,r.hydrated_count,
    latest.status AS latest_status,latest.started_at AS latest_started_at,latest.finished_at AS latest_finished_at
    FROM (SELECT $1::text AS company_id) scope
    LEFT JOIN public.spotlight_import_current c ON c.tenant_key=scope.company_id
    LEFT JOIN public.spotlight_import_runs r ON r.id=c.run_id AND r.tenant_key=scope.company_id
    LEFT JOIN LATERAL (SELECT status,started_at,finished_at FROM public.spotlight_import_runs
      WHERE tenant_key=scope.company_id ORDER BY started_at DESC,id DESC LIMIT 1) latest ON true`, [companyId])).rows[0];
}

/** Explicit injected service only. No initializer, route, scheduler or production pool.
 * Build in a dedicated worker with at least two pool connections; never a page request.
 */
export function createSpotlightSummaryStore(db: Database) {
  async function build(companyId: string, actor: string, options: {
    limits?: typeof summaryLimits; expectedRunId?: string; signal?: AbortSignal;
    checkpoint?: (scanned: number) => Promise<void>;
    beforePublish?: (client: PoolClient) => Promise<void>;
  } = {}) {
    validateSourceRead({ companyId, now: new Date(), staleAfterMs: 86400000 });
    if (!actor || actor.length > 200 || /[\r\n\x00]/.test(actor)) throw new Error("A valid summary builder identity is required.");
    const writer = await db.connect(); let source: PoolClient | undefined, locked = false, destroy = false;
    const started = Date.now();
    const deadline = () => {
      if (options.signal?.aborted) throw new Error("Summary worker stopped; previous summary retained.");
      if (Date.now()-started > 300000) throw new Error("Summary build exceeded five minutes; previous summary retained.");
    };
    try {
      // A single summary build across workers limits memory and source database load.
      locked = (await writer.query("SELECT pg_try_advisory_lock($1,1) AS acquired", [LOCK])).rows[0]?.acquired === true;
      if (!locked) return { state: "busy" as const };
      await writer.query("SELECT 1 FROM public.spotlight_summary_generations LIMIT 0"); // explicit migration required
      source = await db.connect(); await beginRead(source);
      const current = await metadata(source, companyId);
      if (!current?.run_id) { await source.query("COMMIT"); return { state: "no-completed-import" as const }; }
      if (!current.owned_run || current.status !== "completed" || !current.finished_at) throw new Error("Invalid completed source generation.");
      const runId = String(current.run_id);
      if (options.expectedRunId && options.expectedRunId !== runId) {
        await source.query("COMMIT"); return { state: "superseded" as const, runId: options.expectedRunId };
      }
      deadline(); await options.checkpoint?.(0);
      const previous = (await writer.query(`SELECT run_id,model_version FROM public.spotlight_summary_current WHERE company_id=$1`, [companyId])).rows[0];
      if (previous?.run_id === runId && previous.model_version === VERSION) {
        await source.query("COMMIT"); return { state: "reused" as const, runId };
      }
      const integrity = (await source.query(`SELECT COUNT(*) AS records,
        COUNT(*) FILTER (WHERE tenant_key<>$2 OR company_id<>$2) AS misplaced
        FROM public.spotlight_import_records WHERE run_id=$1`, [runId, companyId])).rows[0];
      const total = summaryCount(integrity.records), verified = Number(current.checkpoint_version) >= 2;
      if (summaryCount(integrity.misplaced) || (verified && (current.expected_count == null || total !== summaryCount(current.expected_count) ||
          total !== summaryCount(current.hydrated_count)))) throw new Error("Source generation count or ownership mismatch.");
      const limits = options.limits ?? summaryLimits;
      const accumulator = createSpotlightSummaryAccumulator(companyId, limits);
      if (total > limits.records) throw new Error("Summary record limit exceeded.");
      let after = "";
      for (;;) {
        deadline(); await options.checkpoint?.(accumulator.scanned);
        const rows: SummaryInput[] = (await source.query(`SELECT r.source_id,r.cve,r.status,r.company_id,
          v.id,v.cid,v.aid,v.status AS raw_status,v.cve->>'id' AS raw_cve,v.cve->>'severity' AS raw_severity,
          v.cve->'base_score' AS score,v.suppression_info->'is_suppressed' AS suppressed
          FROM (SELECT source_id,cve,status,company_id,raw FROM public.spotlight_import_records
            WHERE run_id=$1 AND tenant_key=$2 AND source_id>$3 ORDER BY source_id LIMIT 2000) r
          CROSS JOIN LATERAL jsonb_to_record(r.raw) AS v(id text,cid jsonb,aid jsonb,status text,cve jsonb,suppression_info jsonb)
          ORDER BY r.source_id`, [runId, companyId, after])).rows;
        if (!rows.length) break;
        for (const row of rows) accumulator.add(row);
        const next = rows.at(-1)!.source_id;
        if (next === after) throw new Error("Summary source cursor did not advance.");
        after = next;
      }
      const artifact = accumulator.finish();
      if (artifact.scanned !== total) throw new Error("Summary scan did not cover the completed source generation.");
      deadline(); await source.query("COMMIT");
      source.release(); source = undefined;
      await writer.query("BEGIN");
      await writer.query("SET LOCAL statement_timeout='15s'");
      await writer.query("SET LOCAL lock_timeout='2s'");
      await writer.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
      // The short publication transaction pins the source pointer. A new import
      // committed during the scan supersedes this build; do not move the summary backwards.
      const head = (await writer.query(`SELECT c.run_id,r.status FROM public.spotlight_import_current c
        JOIN public.spotlight_import_runs r ON r.id=c.run_id AND r.tenant_key=c.tenant_key
        WHERE c.tenant_key=$1 FOR SHARE OF c`, [companyId])).rows[0];
      if (head?.run_id !== runId || head.status !== "completed") {
        await writer.query("ROLLBACK"); return { state: "superseded" as const, runId };
      }
      await writer.query(`INSERT INTO public.spotlight_summary_generations
        (company_id,run_id,model_version,source_completed_at,source_rows,count_verification,summary,cve_count,built_by)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, [companyId, runId, VERSION, current.finished_at, total,
        verified ? "import-count-reconciled" : "completion-marker-only", JSON.stringify(artifact.summary), artifact.rows.length, actor]);
      for (let offset=0; offset<artifact.rows.length; offset+=500) {
        deadline(); await options.checkpoint?.(artifact.scanned);
        await writer.query(`INSERT INTO public.spotlight_summary_cves(company_id,run_id,model_version,cve,severity,cvss,affected_devices,source_instances)
          SELECT $1,$2,$3,v.cve,v.severity,v.cvss,v.devices,v.findings FROM jsonb_to_recordset($4::jsonb)
          v(cve text,severity text,cvss double precision,devices bigint,findings bigint)`, [companyId,runId,VERSION,
          JSON.stringify(artifact.rows.slice(offset,offset+500).map(v => ({ cve:v.cve,severity:v.severity,cvss:v.cvss,devices:v.affectedDevices,findings:v.sourceInstances })))]);
      }
      deadline(); await options.beforePublish?.(writer);
      await writer.query(`INSERT INTO public.spotlight_summary_current(company_id,run_id,model_version) VALUES($1,$2,$3)
        ON CONFLICT(company_id) DO UPDATE SET run_id=EXCLUDED.run_id,model_version=EXCLUDED.model_version`, [companyId,runId,VERSION]);
      await writer.query("COMMIT");
      return { state: "built" as const, runId, sourceRows: total, cves: artifact.rows.length, elapsedMs: Date.now()-started };
    } catch (error) {
      await source?.query("ROLLBACK").catch(() => {}); await writer.query("ROLLBACK").catch(() => {}); throw error;
    } finally {
      source?.release();
      if (locked) await writer.query("SELECT pg_advisory_unlock($1,1)", [LOCK]).catch(() => { destroy = true; });
      writer.release(destroy);
    }
  }

  async function read(request: CustomerSourceReadRequest): Promise<CustomerSourceRead> {
    const { companyId, now, staleAfterMs, offset, limit } = validateSourceRead(request);
    const base = { version: 1 as const, companyId, source: "crowdstrike" as const, scope: "saved-source-generation" as const,
      definition: spotlightSummaryDefinition, latestAttempt: null as CustomerSourceRead["latestAttempt"], projection: undefined as CustomerSourceRead["projection"] };
    const unavailable = (state: "not-installed" | "no-completed-import" | "summary-pending" | "inconsistent"): CustomerSourceRead =>
      ({ ...base, state, generation: null, summary: null, cves: null });
    const client = await db.connect();
    try {
      await beginRead(client);
      const ready = (await client.query(`SELECT to_regclass('public.spotlight_summary_current') IS NOT NULL
        AND to_regclass('public.spotlight_summary_generations') IS NOT NULL AND to_regclass('public.spotlight_summary_cves') IS NOT NULL
        AND to_regclass('public.spotlight_import_current') IS NOT NULL AND to_regclass('public.spotlight_import_runs') IS NOT NULL AS ready`)).rows[0]?.ready;
      let result: CustomerSourceRead;
      if (!ready) result = unavailable("not-installed");
      else {
        const current = await metadata(client, companyId);
        if (["running","completed","failed"].includes(current?.latest_status)) base.latestAttempt = { status: current.latest_status === "completed" ? "succeeded" : current.latest_status,
          startedAt: iso(current.latest_started_at), finishedAt: current.latest_finished_at == null ? null : iso(current.latest_finished_at) };
        if (!current?.run_id) result = unavailable("no-completed-import");
        else if (!current.owned_run || current.status !== "completed" || !current.finished_at) result = unavailable("inconsistent");
        else {
          const saved = (await client.query(`SELECT g.* FROM public.spotlight_summary_current p JOIN public.spotlight_summary_generations g
            ON g.company_id=p.company_id AND g.run_id=p.run_id AND g.model_version=p.model_version
            WHERE p.company_id=$1 AND p.model_version=$2`, [companyId, VERSION])).rows[0];
          base.projection = { state: saved?.run_id === current.run_id ? "ready" : "pending", currentImportId: current.run_id,
            builtAt: saved ? iso(saved.built_at) : null, modelVersion: VERSION };
          if (!saved) result = unavailable("summary-pending");
          else {
            const aggregate = (await client.query(`SELECT severity,COUNT(*) AS cves,SUM(affected_devices) AS devices,SUM(source_instances) AS findings
              FROM public.spotlight_summary_cves WHERE company_id=$1 AND run_id=$2 AND model_version=$3 GROUP BY severity`, [companyId,saved.run_id,VERSION])).rows;
            const page = (await client.query(`SELECT cve,severity,cvss,affected_devices,source_instances FROM public.spotlight_summary_cves
              WHERE company_id=$1 AND run_id=$2 AND model_version=$3 ORDER BY severity_rank DESC,affected_devices DESC,cve LIMIT $4 OFFSET $5`,
              [companyId,saved.run_id,VERSION,limit,offset])).rows;
            try {
              const summary = saved.summary as SpotlightSummary;
              validateSpotlightSummary(summary, aggregate);
              if (summaryCount(saved.cve_count) !== summary.uniqueCves || page.length !== Math.min(limit,Math.max(0,summary.uniqueCves-offset))) throw new Error("Incomplete summary page.");
              if (summaryCount(saved.source_rows) < summary.sourceInstances + summaryCount(summary.excludedSuppressedInstances) + summary.excludedNonCveInstances) throw new Error("Invalid source row count.");
              const rows: SourceCveRow[] = page.map(v => ({ cve:v.cve,severity:v.severity,cvss:v.cvss,affectedDevices:summaryCount(v.affected_devices),sourceInstances:summaryCount(v.source_instances) }));
              const completedAt = iso(saved.source_completed_at);
              result = { ...base, state: "available", generation: { id:saved.run_id,completedAt,clock:"import-completion",
                connectionRevision:null,importRevision:null,revisionMatches:null,countVerification:saved.count_verification,...importFreshness(completedAt,now,staleAfterMs) },
                summary, cves:{rows,total:summary.uniqueCves,offset,limit} };
            } catch { result = unavailable("inconsistent"); }
          }
        }
      }
      await client.query("COMMIT"); return result;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; } finally { client.release(); }
  }
  return { build, read };
}
