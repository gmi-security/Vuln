import type { Pool } from "pg";
import { summaryCustomers } from "./spotlight-summary-jobs";

export const defaultSummaryRetention = Object.freeze({ keepRecent: 90, maxAgeDays: 365, keepJobs: 100, jobAgeDays: 90, batchSize: 5 });
export type SummaryRetentionPolicy = typeof defaultSummaryRetention;
export function summaryRetentionPolicy(input: Partial<SummaryRetentionPolicy> = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid summary retention policy.");
  const policy = { ...defaultSummaryRetention, ...input };
  const ranges: Record<keyof SummaryRetentionPolicy, readonly [number, number]> = {
    keepRecent: [3, 365], maxAgeDays: [30, 730], keepJobs: [50, 1000], jobAgeDays: [30, 730], batchSize: [1, 5],
  };
  for (const name of Object.keys(policy)) {
    if (!(name in ranges)) throw new Error("Unknown summary retention setting.");
    const key = name as keyof SummaryRetentionPolicy, value = policy[key], [min, max] = ranges[key];
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error("Invalid summary retention setting.");
  }
  return policy;
}

type Generation = { companyId: string; runId: string; modelVersion: number; cveRows: number };
type Job = { companyId: string; runId: string; modelVersion: number };

/** Explicit injected maintenance service. No timer, route, initializer or worker caller.
 * Preview is read-only. Apply reselects candidates under locks, never trusts preview IDs.
 */
export function createSpotlightSummaryRetention(db: Pick<Pool, "connect">) {
  async function run(companyId: string, options: { apply?: boolean; policy?: Partial<SummaryRetentionPolicy> } = {}) {
    if (typeof companyId !== "string") throw new Error("An explicit summary customer ID is required.");
    summaryCustomers([companyId]);
    const policy = summaryRetentionPolicy(options.policy);
    if (options.apply !== undefined && typeof options.apply !== "boolean") throw new Error("Invalid retention mode.");
    const apply = options.apply === true, client = await db.connect(), started = Date.now();
    try {
      await client.query(apply ? "BEGIN" : "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
      if (apply) {
        // Same lock as builders; transactions and session locks conflict with each other.
        const lock = await client.query("SELECT pg_try_advisory_xact_lock(804244,1) AS owned");
        if (!lock.rows[0].owned) { await client.query("ROLLBACK"); return { state: "busy" as const }; }
        // Serialize discovery/claim transitions while protecting active jobs.
        await client.query("SELECT pg_advisory_xact_lock(804246,1)");
        await client.query("SELECT run_id FROM public.spotlight_import_current WHERE tenant_key=$1 FOR SHARE", [companyId]);
      }
      const generations: Generation[] = (await client.query(`WITH ranked AS (
        SELECT g.*,ROW_NUMBER() OVER(ORDER BY built_at DESC,run_id DESC,model_version DESC) AS position
        FROM public.spotlight_summary_generations g WHERE company_id=$1
      ) SELECT company_id AS "companyId",run_id AS "runId",model_version AS "modelVersion",cve_count AS "cveRows"
        FROM ranked g WHERE position>3 AND (position>$2 OR built_at<now()-make_interval(days=>$3))
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_summary_current p
            WHERE (p.company_id,p.run_id,p.model_version)=(g.company_id,g.run_id,g.model_version))
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_import_current c WHERE c.tenant_key=g.company_id AND c.run_id=g.run_id)
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_summary_jobs j
            WHERE (j.company_id,j.run_id,j.model_version)=(g.company_id,g.run_id,g.model_version) AND j.status IN ('queued','running','retry'))
        ORDER BY built_at,run_id,model_version LIMIT $4`, [companyId, policy.keepRecent, policy.maxAgeDays, policy.batchSize + 1])).rows;
      // Select before deleting summaries: their jobs stay through at least one further pass.
      const jobs: Job[] = (await client.query(`WITH ranked AS (
        SELECT j.*,ROW_NUMBER() OVER(ORDER BY finished_at DESC,run_id DESC,model_version DESC) AS position
        FROM public.spotlight_summary_jobs j WHERE company_id=$1
          AND status IN ('succeeded','failed','superseded') AND finished_at IS NOT NULL
      ) SELECT company_id AS "companyId",run_id AS "runId",model_version AS "modelVersion" FROM ranked j
        WHERE (position>$2 OR finished_at<now()-make_interval(days=>$3))
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_summary_generations g
            WHERE (g.company_id,g.run_id,g.model_version)=(j.company_id,j.run_id,j.model_version))
          AND NOT EXISTS (SELECT 1 FROM public.spotlight_import_current c WHERE c.tenant_key=j.company_id AND c.run_id=j.run_id)
        ORDER BY finished_at,run_id,model_version LIMIT 101`, [companyId, policy.keepJobs, policy.jobAgeDays])).rows;
      const selected = generations.slice(0, policy.batchSize), selectedJobs = jobs.slice(0, 100);
      if (apply) {
        for (const item of selected) {
          if (Date.now() - started > 30000) throw new Error("Retention batch deadline exceeded.");
          // Cascade removes only CVE detail rows belonging to this derived generation.
          const deleted = await client.query(`DELETE FROM public.spotlight_summary_generations
            WHERE company_id=$1 AND run_id=$2 AND model_version=$3`, [companyId, item.runId, item.modelVersion]);
          if (deleted.rowCount !== 1) throw new Error("Summary retention candidate changed.");
        }
        for (const item of selectedJobs) {
          if (Date.now() - started > 30000) throw new Error("Retention batch deadline exceeded.");
          const deleted = await client.query(`DELETE FROM public.spotlight_summary_jobs
            WHERE company_id=$1 AND run_id=$2 AND model_version=$3 AND status IN ('succeeded','failed','superseded')`,
          [companyId, item.runId, item.modelVersion]);
          if (deleted.rowCount !== 1) throw new Error("Summary job retention candidate changed.");
        }
      }
      await client.query("COMMIT");
      return { state: apply ? "applied" as const : "preview" as const, companyId, policy,
        generations: selected, jobs: selectedJobs, cveRows: selected.reduce((total, item) => total + item.cveRows, 0),
        moreCandidates: generations.length > selected.length || jobs.length > selectedJobs.length };
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
    finally { client.release(); }
  }
  return { run };
}
