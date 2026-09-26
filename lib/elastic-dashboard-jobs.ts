import { randomUUID } from "node:crypto";
import { DashboardError, parseDefinition, parseQueryInput, querySource } from "./elastic-dashboard";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { dashboardDatabase, dashboardConnectionRevision, prepareConsolidation, preparePatchRequest, previewQuery, saveQuery, throttlePreview } from "./elastic-dashboard-store";
import { parseConsolidationInput, parsePatchInput } from "./patch-request";
import { persistPreparedPatch } from "./patch-ticket-store";

const global = globalThis as typeof globalThis & { __elasticJobs?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = global.__elasticJobs ??= {};

export async function enqueueDashboardJob(kind: "preview" | "save" | "patch" | "consolidate", value: unknown, actor: string) {
  const body = value as Record<string, unknown> | null;
  const input = kind === "patch" ? parsePatchInput(body) : kind === "consolidate" ? parseConsolidationInput(body) : kind === "preview" ? { ...parseQueryInput(body), ...(typeof body?.id === "string" && /^[a-zA-Z0-9-]{1,64}$/.test(body.id) ? { id: body.id } : {}) } : parseDefinition(value, typeof body?.id === "string" ? body.id : randomUUID());
  const revision = await dashboardConnectionRevision(querySource(input));
  if (revision === null) throw new DashboardError(`Connect ${querySource(input) === "elastic" ? "Elasticsearch" : "CrowdStrike"} first.`, 409);
  throttlePreview(actor);
  const db = await dashboardDatabase();
  const client = await db.connect();
  const id = randomUUID();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804202)");
    const count = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_jobs WHERE status IN ('queued', 'running') AND expires_at > now()");
    if (count.rows[0].count >= 2) throw new DashboardError("Two background jobs are already queued or running. Try again after one finishes.", 429);
    const previous = kind === "save" ? await client.query("SELECT revision FROM elastic_dashboard_queries WHERE id = $1", [(input as { id: string }).id]) : null;
    await client.query("INSERT INTO elastic_dashboard_jobs (id, actor, kind, input, connection_revision, query_revision) VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
      [id, actor, kind, JSON.stringify(input), revision, previous?.rows[0]?.revision ?? null]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerDashboardJobs();
  return { jobId: id, status: "queued" };
}

export async function readDashboardJob(id: string, actor: string) {
  if (!/^[a-f0-9-]{36}$/i.test(id)) throw new DashboardError("Query job not found.", 404);
  const db = await dashboardDatabase();
  // These jobs are private to the requesting member. No Elastic IDs or keys are returned.
  const row = (await db.query("SELECT id, status, result, error, input, connection_revision FROM elastic_dashboard_jobs WHERE id = $1 AND actor = $2 AND expires_at > now()", [id, actor])).rows[0];
  if (!row) throw new DashboardError("Query job expired or was not found. Preview again.", 404);
  if (row.connection_revision !== await dashboardConnectionRevision(querySource(row.input))) throw new DashboardError("The connection changed. Preview again.", 409);
  triggerDashboardJobs();
  return { jobId: row.id, status: row.status, ...(row.result ?? {}), ...(row.error ? { error: row.error } : {}) };
}

async function work() {
  if (!elasticVulnEnabled()) return;
  const db = await dashboardDatabase();
  await db.query("UPDATE elastic_dashboard_jobs SET status = 'failed', error = 'The background query was interrupted or expired. Please retry.' WHERE status = 'running' AND started_at < now() - interval '7 minutes'");
  await db.query("DELETE FROM elastic_dashboard_jobs WHERE expires_at <= now()");
  while (elasticVulnEnabled()) {
    // Reserve room for the automatic refresh worker in this process.
    const runtime = globalThis as typeof globalThis & { __elasticDashboard?: { running: number } };
    if ((runtime.__elasticDashboard?.running ?? 0) >= 2) return;
    const client = await db.connect();
    let job;
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(804202)");
      const running = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_jobs WHERE status = 'running'");
      if (running.rows[0].count < 2) {
        job = (await client.query(`UPDATE elastic_dashboard_jobs SET status = 'running', started_at = now()
          WHERE id = (SELECT id FROM elastic_dashboard_jobs WHERE status = 'queued' AND expires_at > now()
            ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *`)).rows[0];
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    if (!job) return;
    try {
      if (job.connection_revision !== await dashboardConnectionRevision(querySource(job.input))) throw new DashboardError("The connection changed. Preview and save again.", 409);
      let result;
      if (job.kind === "save") {
        await saveQuery(job.input, job.actor, { id: job.id, connectionRevision: job.connection_revision, queryRevision: job.query_revision });
        result = { saved: true };
      } else if (job.kind === "patch") {
        const patchRequest = await preparePatchRequest(job.input, job.connection_revision);
        const patchRequestId = await persistPreparedPatch(job.id, patchRequest, job.actor, job.connection_revision);
        result = { patchRequest, patchRequestId };
      } else if (job.kind === "consolidate") {
        result = { consolidation: await prepareConsolidation(job.input, job.connection_revision) };
      } else {
        result = { result: await previewQuery(job.input, job.actor, true, job.input.id) };
      }
      if (job.connection_revision !== await dashboardConnectionRevision(querySource(job.input))) throw new DashboardError("The connection changed. Preview again.", 409);
      await db.query("UPDATE elastic_dashboard_jobs SET status = 'succeeded', result = $2::jsonb WHERE id = $1 AND status = 'running'", [job.id, JSON.stringify(result)]);
    } catch (error) {
      const message = error instanceof DashboardError ? error.message : "Background query failed. Check the connection and retry.";
      await db.query("UPDATE elastic_dashboard_jobs SET status = 'failed', error = $2 WHERE id = $1 AND status = 'running'", [job.id, message]);
    }
  }
}

export function triggerDashboardJobs() {
  if (state.working) return;
  state.working = work().catch(() => console.error("[elastic-dashboard] Background job worker could not complete."))
    .finally(() => { state.working = undefined; });
}

export function startDashboardJobWorker() {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  state.timer = setInterval(triggerDashboardJobs, 15_000);
  state.timer.unref();
  triggerDashboardJobs();
}
