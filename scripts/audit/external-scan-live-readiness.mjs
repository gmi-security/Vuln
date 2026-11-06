#!/usr/bin/env node
/**
 * Read-only external Nessus/Greenbone go-live preflight for Vuln-NYC1.
 *
 * Run with node --env-file=.env --env-file=.env.local
 *   --env-file=.env.production.local scripts/audit/external-scan-live-readiness.mjs
 *
 * Does not enable dispatch, install migrations, create claims, start scans,
 * expose targets/credentials, or modify the SQL authority.
 */
import { pathToFileURL } from "node:url";

const API_BASE = "http://127.0.0.1:3000";
const SOURCES = Object.freeze([
  ["health", "/api/health", false],
  ["plan", "/api/admin/external-scan-plan", true],
  ["capacity", "/api/admin/external-scan-capacity", true],
  ["slot", "/api/admin/external-scan-slot", true],
]);

const validStatus = response => Boolean(response && response.http === 200 && response.body);
const integer = n => Number.isSafeInteger(n) && n >= 0;

export function evaluateReadiness({ probes, database, flags }) {
  const blockers = [];
  const checks = {};
  const fail = (name, reason) => {
    checks[name] = { ready: false, reason };
    blockers.push(name);
  };
  const pass = (name, extra = {}) => { checks[name] = { ready: true, ...extra }; };

  if (validStatus(probes.health) && probes.health.body.ready === true &&
      probes.health.body.readReady === true && probes.health.body.writeReady === true &&
      probes.health.body.persistence?.dbReachable === true &&
      probes.health.body.persistence?.blocked === false)
    pass("application");
  else fail("application", "Application is not fully read/write ready.");

  if (database?.authority?.mode === "sql" && database.authority.enforced === true)
    pass("sqlAuthority", {epoch: database.authority.epoch, revision: database.authority.revision});
  else fail("sqlAuthority", "SQL authority could not be verified.");

  const n = database?.routes?.nessus ?? 0, v = database?.routes?.vulners ?? 0;
  if (integer(n) && integer(v) && n > 0 && v > 0)
    pass("reviewedRoutesExist", {nessusCount:n, vulnersCount:v});
  else fail("reviewedRoutesExist", "No independent Nessus and Greenbone route records verified.");

  const plan = probes.plan?.body;
  if (validStatus(probes.plan) && plan.mode === "preview-only" &&
      plan.launchesEnabled === false && plan.routeStatus === "reviewed" &&
      Array.isArray(plan.candidates) && plan.candidates.length > 0 &&
      Array.isArray(plan.blocked) && plan.blocked.length === 0)
    pass("exactDefinitionPlan", {
      candidateTargetSlots: plan.candidates.length,
      definitionCount: new Set(plan.candidates.map(x => x.nessusScanId)).size,
    });
  else fail("exactDefinitionPlan", "Live, reviewed, fully unblocked per-definition target plan is unavailable.");

  const c = probes.capacity?.body;
  if (validStatus(probes.capacity) && c.scannerCapacityVerified === true &&
      c.capacity?.healthy === true && integer(c.capacity.activeTaskCount) &&
      integer(c.capacity.queuedTaskCount) && integer(c.capacity.requestedTaskCount) &&
      c.capacity.activeTaskCount + c.capacity.queuedTaskCount + c.capacity.requestedTaskCount === 0 &&
      Number.isFinite(Date.parse(c.capacity.checkedAt)) &&
      Date.now() - Date.parse(c.capacity.checkedAt) >= 0 &&
      Date.now() - Date.parse(c.capacity.checkedAt) <= 30000)
    pass("scannerCapacity");
  else fail("scannerCapacity", "Fresh complete GMP capacity attestation is unavailable or the scanner is busy.");

  if (validStatus(probes.slot) && probes.slot.body.slot?.claim_key === null)
    pass("globalReservationSlot");
  else fail("globalReservationSlot", "Global slot schema is unavailable or the slot is occupied.");

  if (flags.VULNERS_BRIDGE_SCHEDULER_ENABLED !== "true")
    pass("legacySchedulerDisabled");
  else fail("legacySchedulerDisabled", "Retired company-wide scheduler must stay disabled.");

  if (flags.GMI_SCAN_ADMISSION_ENABLED === "true" &&
      flags.VULN_EXTERNAL_SCAN_DISPATCH_ENABLED === "true")
    pass("dispatchFlags");
  else fail("dispatchFlags", "New dispatch and admission switches remain disabled.");

  // There is currently NO wired production source for these proofs. Never
  // classify a healthy API, a configured schedule, or empty findings as
  // an approved maintenance window or completed target-by-target scan.
  fail("liveMaintenanceWindow", "No trusted current approved-window adapter is wired to dispatch.");
  fail("completedNessusOccurrence", "Historical Nessus proof adapter is not wired to production dispatch.");
  fail("greenboneTerminalReport", "Verified terminal report/host coverage and safe slot release are not wired.");

  return {
    audit: "read-only-external-scan-go-live",
    outcome: "HOLD",
    checks,
    blockers,
    note: "No targets or customer names are disclosed. Passing configured-scope parity is not completed scan parity.",
  };
}

export async function getProbe(path, token, timeoutMs = 15000) {
  try {
    const response = await fetch(API_BASE + path, {
      method: "GET",
      headers: token ? { Authorization: "Bearer " + token } : {},
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const body = await response.json().catch(() => null);
    return {http: response.status, body};
  } catch {
    return {http: 0, body: null};
  }
}

async function readDatabase() {
  const url = process.env.DATABASE_URL;
  if (!url) return null;
  const { default: pg } = await import("pg");
  const { applicationDatabaseSsl } = await import("../../lib/db/connection-target.mjs");
  const client = new pg.Client({
    connectionString: url,
    ssl: applicationDatabaseSsl(url),
    application_name: "vuln-external-scan-go-live-readonly",
    connectionTimeoutMillis: 15000,
    options: "-c default_transaction_read_only=on -c statement_timeout=15000",
  });
  let begun = false;
  try {
    await client.connect();
    await client.query("BEGIN READ ONLY"); begun = true;
    const tables = (await client.query(
      "SELECT to_regclass('public.app_store_authority') IS NOT NULL AS authority," +
      "to_regclass('public.customer_scanner_routes') IS NOT NULL AS routes"
    )).rows[0];
    const result = {authority:null, routes:{nessus:0,vulners:0}};
    if (tables.authority) {
      result.authority = (await client.query(
        "SELECT mode,enforced,epoch::text,revision::text FROM public.app_store_authority WHERE id=1"
      )).rows[0] ?? null;
    }
    if (tables.routes) {
      const rows = (await client.query(
        "SELECT provider,count(*)::int AS count FROM public.customer_scanner_routes " +
        "WHERE enabled=true AND provider IN ('nessus','vulners') GROUP BY provider"
      )).rows;
      for (const row of rows) result.routes[row.provider] = row.count;
    }
    await client.query("COMMIT"); begun = false;
    return result;
  } catch {
    return null;
  } finally {
    if (begun) await client.query("ROLLBACK").catch(() => {});
    await client.end().catch(() => {});
  }
}

export async function main() {
  const token = process.env.ADMIN_TOKEN?.trim();
  const entries = await Promise.all(SOURCES.map(async ([name, path, auth]) =>
    [name, auth && !token ? {http:401,body:null} : await getProbe(path, auth ? token : null)]
  ));
  const probes = Object.fromEntries(entries);
  const result = evaluateReadiness({probes, database:await readDatabase(), flags:process.env});
  // The raw API responses include potentially sensitive targets and task details.
  // Output ONLY the reduced, sanitized gate verdicts.
  console.log(JSON.stringify(result, null, 2));
  // HOLD is expected until the missing production adapters and customer
  // approvals have been implemented. Fail the CI/operator gate, not the app.
  process.exitCode = result.blockers.length ? 2 : 0;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error("Read-only go-live audit failed closed.");
    process.exitCode = 2;
  });
}
