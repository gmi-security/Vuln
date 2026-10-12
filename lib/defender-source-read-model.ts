import type { Pool } from "pg";
import {
  emptySeverityCounts, importFreshness, sourceSeverities, validateSourceRead,
  type CustomerSourceRead, type CustomerSourceReadRequest, type SeverityCounts, type SourceCveRow,
} from "./customer-source-read-model";

function count(value: unknown): number {
  if (typeof value !== "number" && (typeof value !== "string" || !/^\d+$/.test(value))) throw new Error("Invalid saved count.");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("Invalid saved count.");
  return n;
}
function timestamp(value: unknown): string {
  if (!(value instanceof Date) && typeof value !== "string") throw new Error("Invalid saved timestamp.");
  return new Date(value).toISOString();
}
function severity(value: unknown): keyof SeverityCounts {
  if (!sourceSeverities.includes(value as keyof SeverityCounts)) throw new Error("Invalid saved severity.");
  return value as keyof SeverityCounts;
}
function score(value: unknown): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 10) throw new Error("Invalid saved score.");
  return value;
}

/** No singleton, schema initialization, hydration, publication or vendor calls.
 * Inject a pool only after customer authorization. Registry preview callers also
 * pin the reviewed tenant/revision; default platform reporting is unchanged.
 */
export function createDefenderSourceReader(db: Pick<Pool, "connect">) {
  return async function read(request: CustomerSourceReadRequest): Promise<CustomerSourceRead> {
    const { companyId, now, staleAfterMs, offset, limit } = validateSourceRead(request);
    const client = await db.connect();
    const base = { version: 1 as const, companyId, source: "defender" as const,
      definition: { instanceUnit: "device-cve-software-version" as const, severityBasis: "source-cvss" as const, suppression: "not-recorded" as const },
      scope: "saved-source-generation" as const, latestAttempt: null as CustomerSourceRead["latestAttempt"] };
    function unavailable(state: "not-installed" | "not-configured" | "no-completed-import" | "inconsistent"): CustomerSourceRead {
      return { ...base, state, generation: null, summary: null, cves: null };
    }
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
      const installed = (await client.query(`SELECT to_regclass('public.defender_connections') IS NOT NULL
        AND to_regclass('public.defender_import_runs') IS NOT NULL
        AND to_regclass('public.defender_cves') IS NOT NULL AS ready`)).rows[0]?.ready;
      let result: CustomerSourceRead;
      if (!installed) result = unavailable("not-installed");
      else {
        // Repeatable-read pins metadata and aggregates without locking the importer/pruner.
        const saved = (await client.query(`SELECT c.current_run, c.tenant_id, c.revision AS connection_revision,
          r.id AS run_id, r.revision AS import_revision, r.status, r.finished_at, r.summary,
          latest.status AS latest_status, latest.started_at AS latest_started_at, latest.finished_at AS latest_finished_at
          FROM public.defender_connections c
          LEFT JOIN public.defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id
          LEFT JOIN LATERAL (SELECT status,started_at,finished_at FROM public.defender_import_runs
            WHERE company_id=c.company_id ORDER BY started_at DESC,id DESC LIMIT 1) latest ON true
          WHERE c.company_id=$1`, [companyId])).rows[0];
        if (request.defenderConnection && (!saved || saved.tenant_id !== request.defenderConnection.tenantId ||
            Number(saved.connection_revision) !== request.defenderConnection.revision ||
            (saved.current_run && Number(saved.import_revision) !== request.defenderConnection.revision))) {
          // Check before reading CVE rows, in the same snapshot as the generation.
          // A previous tenant's completed import must not satisfy a new binding.
          result = unavailable("inconsistent");
        }
        else if (!saved) result = unavailable("not-configured");
        else {
          if (["queued", "running", "succeeded", "failed"].includes(saved.latest_status)) {
            base.latestAttempt = { status: saved.latest_status, startedAt: timestamp(saved.latest_started_at),
              finishedAt: saved.latest_finished_at == null ? null : timestamp(saved.latest_finished_at) };
          }
          if (!saved.current_run) result = unavailable("no-completed-import");
          else if (!saved.run_id || saved.status !== "succeeded" || !saved.finished_at || !saved.summary) result = unavailable("inconsistent");
          else {
            const aggregates = (await client.query(`SELECT severity,COUNT(*) AS cves,
              SUM(devices) AS devices,SUM(findings) AS findings
              FROM public.defender_cves WHERE run_id=$1 GROUP BY severity`, [saved.run_id])).rows;
            const rows = (await client.query(`SELECT cve,severity,cvss,devices,findings FROM public.defender_cves
              WHERE run_id=$1 ORDER BY severity_rank DESC,devices DESC,cve LIMIT $2 OFFSET $3`, [saved.run_id, limit, offset])).rows;
            // Corrupt/incomplete persisted summaries must never become an apparent zero result.
            try {
              const summary = saved.summary;
              const sourceInstances = count(summary.findings), uniqueCves = count(summary.cves);
              const affectedDevices = count(summary.affectedDevices), inventoryDevices = count(summary.inventoryDevices);
              const instanceSeverity = emptySeverityCounts(), cveSeverity = emptySeverityCounts();
              if (!summary.severity || typeof summary.severity !== "object" || Array.isArray(summary.severity)) throw new Error();
              for (const [key, value] of Object.entries(summary.severity)) instanceSeverity[severity(key)] = count(value);
              let deviceCveFindings = 0, instances = 0;
              for (const row of aggregates) {
                cveSeverity[severity(row.severity)] = count(row.cves);
                const devices = count(row.devices), findings = count(row.findings), cves = count(row.cves);
                if (devices < cves || findings < devices) throw new Error();
                deviceCveFindings += devices; instances += findings;
              }
              if (Object.values(instanceSeverity).reduce((a,b) => a+b, 0) !== sourceInstances ||
                  Object.values(cveSeverity).reduce((a,b) => a+b, 0) !== uniqueCves || instances !== sourceInstances ||
                  !Number.isSafeInteger(deviceCveFindings) || affectedDevices > deviceCveFindings ||
                  (sourceInstances > 0 && affectedDevices === 0)) throw new Error();
              const cves: SourceCveRow[] = rows.map(row => {
                if (!/^CVE-\d{4}-\d{4,}$/.test(row.cve)) throw new Error();
                const devices = count(row.devices), findings = count(row.findings);
                if (devices < 1 || findings < devices) throw new Error();
                return { cve: row.cve, severity: severity(row.severity), cvss: score(row.cvss), affectedDevices: devices, sourceInstances: findings };
              });
              if (cves.length !== Math.min(limit, Math.max(0, uniqueCves-offset))) throw new Error();
              const completedAt = timestamp(saved.finished_at);
              const connectionRevision = count(saved.connection_revision), importRevision = count(saved.import_revision);
              if (connectionRevision < 1 || importRevision < 1) throw new Error();
              result = { ...base, state: "available", generation: { id: saved.run_id, completedAt,
                connectionRevision, importRevision, revisionMatches: connectionRevision === importRevision,
                clock: "import-completion", countVerification: "summary-reconciled", ...importFreshness(completedAt, now, staleAfterMs) },
                summary: { sourceInstances, deviceCveFindings, uniqueCves, affectedDevices, inventoryDevices,
                  unknownSuppressionInstances: null, excludedSuppressedInstances: null, excludedNonCveInstances: 0,
                  severity: { sourceInstances: instanceSeverity, uniqueCves: cveSeverity } },
                cves: { rows: cves, total: uniqueCves, offset, limit } };
            } catch { result = unavailable("inconsistent"); }
          }
        }
      }
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error; // Infrastructure failures remain failures; callers may retain a labelled previous result.
    } finally { client.release(); }
  };
}
