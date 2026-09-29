import { patchTicketDatabase } from "./patch-ticket-store";

// A fire-and-forget trigger (validate-closures, abandon-and-replace,
// close-and-recut) returns before its work finishes, on purpose -- the
// dashboard's request client aborts after 20 seconds and these can run for
// minutes. But that leaves nothing to check afterward except guessing from
// side effects (did "Prepared" go up yet?). This is the one place each of
// those passes records what actually happened, so a stuck-looking run can
// be told apart from a slow one, and a silent failure stops being silent.
export type JobRunStatus = "running" | "succeeded" | "failed";
export type JobRun = { job: string; status: JobRunStatus; result: unknown; error: string | null; startedAt: string; finishedAt: string | null };

export async function recordJobRun(job: string, status: JobRunStatus, result?: unknown, error?: string): Promise<void> {
  const db = await patchTicketDatabase();
  await db.query(`INSERT INTO background_job_runs(job,status,result,error,started_at,finished_at)
    VALUES($1,$2,$3::jsonb,$4,now(),${status === "running" ? "NULL" : "now()"})
    ON CONFLICT(job) DO UPDATE SET status=EXCLUDED.status, result=EXCLUDED.result, error=EXCLUDED.error,
      started_at=CASE WHEN EXCLUDED.status='running' THEN now() ELSE background_job_runs.started_at END,
      finished_at=EXCLUDED.finished_at`,
    [job, status, result !== undefined ? JSON.stringify(result) : null, error ?? null]);
}

export async function getJobRun(job: string): Promise<JobRun | null> {
  const db = await patchTicketDatabase();
  const row = (await db.query("SELECT job, status, result, error, started_at, finished_at FROM background_job_runs WHERE job=$1", [job])).rows[0] as
    { job: string; status: JobRunStatus; result: unknown; error: string | null; started_at: string; finished_at: string | null } | undefined;
  if (!row) return null;
  return { job: row.job, status: row.status, result: row.result, error: row.error,
    startedAt: new Date(row.started_at).toISOString(), finishedAt: row.finished_at ? new Date(row.finished_at).toISOString() : null };
}
