import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { validateSourceRead } from "./customer-source-read-model";
import { SPOTLIGHT_SUMMARY_VERSION as VERSION } from "./spotlight-summary-model";

export type SummaryClaim = { companyId: string; runId: string; token: string; attempts: number };
export class SummaryLeaseLost extends Error { constructor() { super("Summary job lease is no longer owned by this worker."); } }
export function summaryCustomers(values: readonly string[]) {
  if (!values.length || values.length > 100) throw new Error("An explicit summary customer list is required (1–100 IDs).");
  for (const companyId of values) validateSourceRead({ companyId, now: new Date(), staleAfterMs: 86400000 });
  return [...new Set(values)].sort();
}
type Database = Pick<Pool,"connect"|"query">;
export function createSpotlightSummaryJobs(db: Database) {
  async function transaction<T>(action: (client:PoolClient)=>Promise<T>) {
    const client=await db.connect();
    try {
      await client.query("BEGIN"); await client.query("SET LOCAL statement_timeout='15s'"); await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SELECT pg_advisory_xact_lock(804246,1)");
      const result=await action(client); await client.query("COMMIT"); return result;
    } catch(error) {await client.query("ROLLBACK").catch(()=>{});throw error;} finally {client.release();}
  }
  async function assertReady() {
    const result=await db.query(`SELECT to_regclass('public.spotlight_summary_jobs') IS NOT NULL
      AND to_regclass('public.spotlight_summary_generations') IS NOT NULL AND to_regclass('public.spotlight_summary_current') IS NOT NULL
      AND to_regclass('public.spotlight_summary_cves') IS NOT NULL AND to_regclass('public.spotlight_import_runs') IS NOT NULL
      AND to_regclass('public.spotlight_import_current') IS NOT NULL AND to_regclass('public.spotlight_import_records') IS NOT NULL AS ready`);
    if (!result.rows[0]?.ready) throw new Error("Summary worker migrations are not installed.");
  }
  async function discover(values:readonly string[]) {
    const customers=summaryCustomers(values);
    return transaction(async client=>{
      // Recover the commit-before-acknowledgement crash window without rebuilding.
      await client.query(`UPDATE public.spotlight_summary_jobs j SET status='succeeded',lease_token=NULL,lease_until=NULL,
        finished_at=COALESCE(j.finished_at,clock_timestamp()),updated_at=clock_timestamp(),last_error_code=NULL,
        source_rows=g.source_rows FROM public.spotlight_summary_generations g
        WHERE j.company_id=ANY($1::text[]) AND j.model_version=$2 AND j.status<>'succeeded'
          AND (g.company_id,g.run_id,g.model_version)=(j.company_id,j.run_id,j.model_version)`,[customers,VERSION]);
      await client.query(`UPDATE public.spotlight_summary_jobs j SET status='superseded',lease_token=NULL,lease_until=NULL,
        finished_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE j.company_id=ANY($1::text[]) AND j.model_version=$2 AND j.status IN ('queued','retry')
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_import_current c JOIN public.spotlight_import_runs r
            ON r.id=c.run_id AND r.tenant_key=c.tenant_key WHERE c.tenant_key=j.company_id AND c.run_id=j.run_id AND r.status='completed')`,[customers,VERSION]);
      const inserted=await client.query(`INSERT INTO public.spotlight_summary_jobs(company_id,run_id,model_version)
        SELECT c.tenant_key,c.run_id,$2 FROM public.spotlight_import_current c JOIN public.spotlight_import_runs r
          ON r.id=c.run_id AND r.tenant_key=c.tenant_key
        WHERE c.tenant_key=ANY($1::text[]) AND r.status='completed' AND r.finished_at IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_summary_generations g
            WHERE g.company_id=c.tenant_key AND g.run_id=c.run_id AND g.model_version=$2)
        ON CONFLICT(company_id,run_id,model_version) DO NOTHING`,[customers,VERSION]);
      return inserted.rowCount ?? 0;
    });
  }
  async function claim(values:readonly string[]):Promise<SummaryClaim|null> {
    const customers=summaryCustomers(values);
    return transaction(async client=>{
      await client.query(`UPDATE public.spotlight_summary_jobs SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'retry' END,
        available_at=clock_timestamp()+CASE WHEN attempts=1 THEN interval '1 minute' ELSE interval '5 minutes' END,
        lease_token=NULL,lease_until=NULL,last_error_code='lease-expired',updated_at=clock_timestamp(),
        finished_at=CASE WHEN attempts>=3 THEN clock_timestamp() ELSE NULL END
        WHERE company_id=ANY($1::text[]) AND model_version=$2 AND status='running' AND lease_until<=clock_timestamp()`,[customers,VERSION]);
      const token=randomUUID();
      const row=(await client.query(`UPDATE public.spotlight_summary_jobs j SET status='running',attempts=attempts+1,
        lease_token=$3,lease_until=clock_timestamp()+interval '60 seconds',started_at=clock_timestamp(),updated_at=clock_timestamp(),source_rows=0
        WHERE (j.company_id,j.run_id,j.model_version)=(SELECT company_id,run_id,model_version FROM public.spotlight_summary_jobs
          WHERE company_id=ANY($1::text[]) AND model_version=$2 AND status IN ('queued','retry') AND attempts<3
            AND available_at<=clock_timestamp() ORDER BY available_at,created_at,company_id,run_id LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING company_id,run_id,attempts`,[customers,VERSION,token])).rows[0];
      return row ? {companyId:row.company_id,runId:row.run_id,token,attempts:row.attempts} : null;
    });
  }
  async function heartbeat(job:SummaryClaim,scanned:number,client:Pick<PoolClient,"query">=db) {
    if(!Number.isSafeInteger(scanned)||scanned<0) throw new Error("Invalid summary progress.");
    const result=await client.query(`UPDATE public.spotlight_summary_jobs SET lease_until=clock_timestamp()+interval '60 seconds',
      source_rows=GREATEST(source_rows,$5),updated_at=clock_timestamp()
      WHERE company_id=$1 AND run_id=$2 AND model_version=$3 AND status='running' AND lease_token=$4 AND lease_until>clock_timestamp()`,
      [job.companyId,job.runId,VERSION,job.token,scanned]);
    if(result.rowCount!==1) throw new SummaryLeaseLost();
  }
  async function finish(job:SummaryClaim,outcome:"succeeded"|"superseded"|"busy"|"build-failed"|"worker-stopped") {
    const success=outcome==='succeeded',terminal=success||outcome==='superseded',busy=outcome==='busy';
    const result=await db.query(`UPDATE public.spotlight_summary_jobs SET
      status=CASE WHEN $5 THEN $6 WHEN $7 THEN 'queued' WHEN attempts>=3 THEN 'failed' ELSE 'retry' END,
      attempts=CASE WHEN $7 THEN attempts-1 ELSE attempts END,
      available_at=clock_timestamp()+CASE WHEN $7 OR attempts=1 THEN interval '1 minute' ELSE interval '5 minutes' END,
      last_error_code=CASE WHEN $5 OR $7 THEN NULL ELSE $6 END,
      finished_at=CASE WHEN $5 OR (attempts>=3 AND NOT $7) THEN clock_timestamp() ELSE NULL END,
      lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
      WHERE company_id=$1 AND run_id=$2 AND model_version=$3 AND status='running' AND lease_token=$4 AND lease_until>clock_timestamp()`,
      [job.companyId,job.runId,VERSION,job.token,terminal,outcome,busy]);
    return result.rowCount===1;
  }
  async function list(companyId:string) {
    summaryCustomers([companyId]);
    return (await db.query(`SELECT company_id AS "companyId",run_id AS "runId",model_version AS "modelVersion",status,attempts,
      source_rows AS "sourceRows",last_error_code AS "errorCode",available_at AS "availableAt",started_at AS "startedAt",
      finished_at AS "finishedAt",updated_at AS "updatedAt" FROM public.spotlight_summary_jobs
      WHERE company_id=$1 ORDER BY created_at DESC,run_id DESC LIMIT 50`,[companyId])).rows;
  }
  return {assertReady,discover,claim,heartbeat,finish,list};
}
