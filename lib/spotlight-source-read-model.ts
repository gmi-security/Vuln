import type { Pool } from "pg";
import { emptySeverityCounts, importFreshness, sourceSeverities, validateSourceRead,
  type CustomerSourceRead, type CustomerSourceReadRequest, type SourceCveRow } from "./customer-source-read-model";

// One bounded database query computes a consistent summary and CVE page. Raw vendor
// payloads never leave PostgreSQL. This remains an offline parity reader until its
// full-generation cost and source authority have passed the release gates.
export const spotlightSourceAggregateSql = `WITH open_rows AS MATERIALIZED (
  SELECT r.cve, r.source_id, v.id AS raw_id, UPPER(v.cve->>'id') AS raw_cve,
    LOWER(v.status) AS raw_status,
    CASE WHEN jsonb_typeof(v.cid)='string' THEN NULLIF(v.cid#>>'{}','') END AS cid,
    CASE WHEN jsonb_typeof(v.aid)='string' THEN NULLIF(v.aid#>>'{}','') END AS aid,
    UPPER(v.cve->>'severity') AS severity,
    CASE WHEN jsonb_typeof(v.cve->'base_score') IN ('number','string')
      AND (v.cve->>'base_score') ~ '^[0-9]{1,2}(\\.[0-9]{1,10})?$'
      THEN (v.cve->>'base_score')::double precision END AS score,
    v.suppression_info->'is_suppressed' AS suppressed
  FROM public.spotlight_import_records r
  CROSS JOIN LATERAL jsonb_to_record(r.raw) AS v(id text,cid jsonb,aid jsonb,status text,cve jsonb,suppression_info jsonb)
  WHERE r.run_id=$1 AND r.tenant_key=$2 AND r.company_id=$2 AND r.status IN ('open','reopen')
), eligible AS MATERIALIZED (
  SELECT *, CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4
    WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END AS severity_rank
  FROM open_rows WHERE suppressed IS DISTINCT FROM 'true'::jsonb AND cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
), device_cves AS MATERIALIZED (
  SELECT cve,cid,aid,MAX(severity_rank) AS severity_rank,
    MAX(score) FILTER (WHERE score BETWEEN 0 AND 10) AS cvss,COUNT(*) AS findings
  FROM eligible GROUP BY cve,cid,aid
), cves AS MATERIALIZED (
  SELECT cve,MAX(severity_rank) AS severity_rank,MAX(cvss) AS cvss,COUNT(*) AS devices,SUM(findings) AS findings
  FROM device_cves GROUP BY cve
), totals AS (
  SELECT COUNT(*) AS instances,
    (SELECT COUNT(*) FROM (SELECT cid,aid FROM device_cves GROUP BY cid,aid) hosts) AS devices,
    COUNT(*) FILTER (WHERE suppressed IS DISTINCT FROM 'false'::jsonb) AS unknown_suppression,
    COUNT(*) FILTER (WHERE cid IS NULL OR aid IS NULL OR raw_cve IS DISTINCT FROM cve
      OR raw_id IS DISTINCT FROM source_id OR raw_status IS NULL OR raw_status NOT IN ('open','reopen')) AS invalid
  FROM eligible
), exclusions AS (
  SELECT COUNT(*) FILTER (WHERE suppressed='true'::jsonb) AS suppressed,
    COUNT(*) FILTER (WHERE suppressed IS DISTINCT FROM 'true'::jsonb AND cve !~ '^CVE-[0-9]{4}-[0-9]{4,}$') AS non_cve
  FROM open_rows
)
SELECT totals.*, exclusions.suppressed,exclusions.non_cve,
  (SELECT COUNT(*) FROM cves) AS unique_cves,
  COALESCE((SELECT SUM(devices) FROM cves),0) AS device_cves,
  COALESCE((SELECT jsonb_object_agg(label,n) FROM (
    SELECT (ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[severity_rank] AS label,COUNT(*) AS n
    FROM eligible GROUP BY severity_rank) s),'{}'::jsonb) AS instance_severity,
  COALESCE((SELECT jsonb_object_agg(label,n) FROM (
    SELECT (ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[severity_rank] AS label,COUNT(*) AS n
    FROM cves GROUP BY severity_rank) s),'{}'::jsonb) AS cve_severity,
  COALESCE((SELECT jsonb_agg(page ORDER BY severity_rank DESC,devices DESC,cve) FROM (
    SELECT cve,(ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[severity_rank] AS severity,
      severity_rank,cvss,devices,findings FROM cves ORDER BY severity_rank DESC,devices DESC,cve LIMIT $3 OFFSET $4
  ) page),'[]'::jsonb) AS page
FROM totals CROSS JOIN exclusions`;

function count(value: unknown): number {
  if (typeof value !== "number" && (typeof value !== "string" || !/^\d+$/.test(value))) throw new Error("Invalid saved count.");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("Invalid saved count.");
  return n;
}
function iso(value: unknown): string {
  if (!(value instanceof Date) && typeof value !== "string") throw new Error("Invalid saved timestamp.");
  return new Date(value).toISOString();
}

export function createSpotlightSourceReader(db: Pick<Pool, "connect">) {
  return async (request: CustomerSourceReadRequest): Promise<CustomerSourceRead> => {
    const { companyId, now, staleAfterMs, offset, limit } = validateSourceRead(request);
    const base = { version: 1 as const, companyId, source: "crowdstrike" as const, scope: "saved-source-generation" as const,
      definition: { instanceUnit: "spotlight-finding" as const, severityBasis: "source-cvss" as const, suppression: "exclude-confirmed-suppressed" as const },
      latestAttempt: null as CustomerSourceRead["latestAttempt"] };
    const unavailable = (state: "not-installed" | "no-completed-import" | "inconsistent"): CustomerSourceRead =>
      ({ ...base, state, generation: null, summary: null, cves: null });
    const client = await db.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
      const installed = (await client.query(`SELECT to_regclass('public.spotlight_import_current') IS NOT NULL
        AND to_regclass('public.spotlight_import_runs') IS NOT NULL
        AND to_regclass('public.spotlight_import_records') IS NOT NULL AS ready`)).rows[0]?.ready;
      let result: CustomerSourceRead;
      if (!installed) result = unavailable("not-installed");
      else {
        // Legacy tenant_key is the app company ID, not a verified Falcon CID.
        const saved = (await client.query(`SELECT c.run_id,r.id AS owned_run,r.status,r.finished_at,
          r.checkpoint_version,r.expected_count,r.hydrated_count,
          latest.status AS latest_status,latest.started_at AS latest_started_at,latest.finished_at AS latest_finished_at
          FROM (SELECT $1::text AS company_id) scope
          LEFT JOIN public.spotlight_import_current c ON c.tenant_key=scope.company_id
          LEFT JOIN public.spotlight_import_runs r ON r.id=c.run_id AND r.tenant_key=scope.company_id
          LEFT JOIN LATERAL (SELECT status,started_at,finished_at FROM public.spotlight_import_runs
            WHERE tenant_key=scope.company_id ORDER BY started_at DESC,id DESC LIMIT 1) latest ON true`, [companyId])).rows[0];
        if (["running", "completed", "failed"].includes(saved?.latest_status)) base.latestAttempt = {
          status: saved.latest_status === "completed" ? "succeeded" : saved.latest_status,
          startedAt: iso(saved.latest_started_at), finishedAt: saved.latest_finished_at == null ? null : iso(saved.latest_finished_at) };
        if (!saved?.run_id) result = unavailable("no-completed-import");
        else if (!saved.owned_run || saved.status !== "completed" || !saved.finished_at) result = unavailable("inconsistent");
        else {
          // A misplaced row invalidates the generation rather than silently hiding part of it.
          const integrity = (await client.query(`SELECT COUNT(*) AS records,
            COUNT(*) FILTER (WHERE tenant_key<>$2 OR company_id<>$2) AS misplaced
            FROM public.spotlight_import_records WHERE run_id=$1`, [saved.run_id, companyId])).rows[0];
          const counted = Number(saved.checkpoint_version) >= 2;
          if (count(integrity.misplaced) > 0 || (counted && (saved.expected_count == null ||
              count(integrity.records) !== count(saved.expected_count) || count(saved.hydrated_count) !== count(saved.expected_count)))) result = unavailable("inconsistent");
          else {
            const row = (await client.query(spotlightSourceAggregateSql, [saved.run_id, companyId, limit, offset])).rows[0];
            if (!row || count(row.invalid) > 0) result = unavailable("inconsistent");
            else {
              const instances = count(row.instances), uniqueCves = count(row.unique_cves);
              const distribution = (raw: Record<string, unknown>, expected: number) => {
                const values = emptySeverityCounts();
                for (const [key,value] of Object.entries(raw)) {
                  if (!sourceSeverities.includes(key as keyof typeof values)) throw new Error("Invalid source severity.");
                  values[key as keyof typeof values] = count(value);
                }
                if (Object.values(values).reduce((a,b) => a+b,0) !== expected) throw new Error("Inconsistent source counts.");
                return values;
              };
              const rows: SourceCveRow[] = row.page.map((v: {cve:string;severity:SourceCveRow['severity'];cvss:number|null;devices:unknown;findings:unknown}) =>
                ({ cve: v.cve, severity: v.severity, cvss: v.cvss, affectedDevices: count(v.devices), sourceInstances: count(v.findings) }));
              if (rows.length !== Math.min(limit, Math.max(0, uniqueCves-offset))) throw new Error("Incomplete CVE page.");
              const completedAt = iso(saved.finished_at);
              result = { ...base, state: "available", generation: { id: saved.run_id, completedAt, clock: "import-completion",
                countVerification: counted ? "import-count-reconciled" : "completion-marker-only",
                connectionRevision: null, importRevision: null, revisionMatches: null, ...importFreshness(completedAt, now, staleAfterMs) },
                summary: { sourceInstances: instances, deviceCveFindings: count(row.device_cves), uniqueCves,
                  affectedDevices: count(row.devices), inventoryDevices: null, unknownSuppressionInstances: count(row.unknown_suppression),
                  excludedSuppressedInstances: count(row.suppressed), excludedNonCveInstances: count(row.non_cve),
                  severity: { sourceInstances: distribution(row.instance_severity, instances), uniqueCves: distribution(row.cve_severity, uniqueCves) } },
                cves: { rows, total: uniqueCves, offset, limit } };
            }
          }
        }
      }
      await client.query("COMMIT"); return result;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
    finally { client.release(); }
  };
}
