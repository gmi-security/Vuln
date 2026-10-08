// node --experimental-vm-modules tests/sla-unification.test.mjs
//
// Exercises computeRemediationSla, computeMetrics, and computeComposite
// (lib/store.ts) against the org's real, configurable Settings > SLA
// instead of the three separate hardcoded day-threshold constants
// (SLA_DAYS, COMPOSITE_SLA_DAYS, and a second copy of SLA_DAYS) that used
// to exist independently of it and of each other. Also confirms Info
// severity findings carry no SLA clock (consistent with findingSlaInfo's
// existing documented behavior) and are excluded from every SLA
// computation rather than silently getting a lenient fallback.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const ROOT = resolve("."), modules = new Map();
async function getModule(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const promise = (async () => new SourceTextModule(ts.transpileModule(await readFile(path, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText, { identifier: path }))();
  modules.set(path, promise); return promise;
}
async function linker(name, parent) {
  if (name.startsWith(".")) return getModule(resolve(dirname(parent.identifier), `${name}.ts`));
  if (name.startsWith("@/")) return getModule(resolve(ROOT, `${name.slice(2)}.ts`));
  const imported = await import(name), values = name === "rrule" ? { ...imported.default, ...imported } : imported;
  return new SyntheticModule(Object.keys(values), function () { for (const k of Object.keys(values)) this.setExport(k, values[k]); });
}
async function load(path) { const m = await getModule(path); if (m.status === "unlinked") await m.link(linker); return m; }
const storeModule = await load("lib/store.ts");
await storeModule.evaluate();
const store = storeModule.namespace;

const company = { id: "CO-TEST", name: "Example Customer", kind: "client", industry: "Test", createdAt: "2026-01-01T00:00:00Z", contactName: "", contactEmail: "" };

// Deliberately distinct from both the old hardcoded SLA_DAYS (7/30/90/180)
// and the default Settings > SLA (7/30/60/90) -- a test that only passes
// because computeRemediationSla et al. actually read THIS value, not any
// leftover hardcoded fallback.
const CUSTOM_SLA = { Critical: 1, High: 5, Medium: 20, Low: 40 };

function daysAgo(n) {
  return new Date(Date.now() - n * 86_400_000).toISOString();
}

function baseFinding(overrides = {}) {
  return {
    id: overrides.id ?? "VLN-1", scanId: "SCAN-1", companyId: company.id, companyName: company.name,
    connector: "nessus", cve: "CVE-2026-1000", title: "Test finding", severity: "High",
    cvss: 5, cvssV2: 0, cvssV3: 5, vpr: 0, epss: 0, asset: "host-1", port: "N/A",
    category: "Test", description: "", remediation: "", status: "Open", assignee: null,
    firstSeen: daysAgo(0), lastSeen: daysAgo(0), resolvedAt: null,
    exploitAvailable: false, kev: false, ransomware: false,
    assetExposure: "Internal", assetCriticality: "Normal", assetSource: "inferred",
    realRisk: 0, riskPriority: "Low",
    ...overrides,
  };
}

function fixture(findings) {
  const s = {
    companies: new Map([[company.id, company]]), folders: new Map(), scans: new Map(), findings: new Map(findings.map((f) => [f.id, f])), assets: new Map(),
    compensatingControls: new Map(), identityAliases: new Map(),
    settings: { autoScanNewAssets: false, schedule: { autoSyncEnabled: false, alertsEnabled: false, monthlyReportsEnabled: false, autoSyncIntervalHours: 24 }, sla: CUSTOM_SLA },
    meta: { defenderGenerations: {} }, seeded: true, counter: 1000,
  };
  globalThis.__vulnStore = s;
  return s;
}

test("computeRemediationSla uses the org's configured Settings > SLA, not a hardcoded constant", () => {
  // High's custom threshold is 5 days -- 6 days old breaches it, even
  // though it's well within both the old hardcoded 30-day High threshold
  // and the default Settings > SLA's own 30-day High threshold.
  fixture([baseFinding({ id: "VLN-1", severity: "High", firstSeen: daysAgo(6) })]);
  const result = store.computeRemediationSla();
  const row = result.clients.find((c) => c.companyId === company.id);
  assert.ok(row, "the company should appear in the per-client breakdown");
  assert.equal(row.open, 1);
  assert.equal(row.breached, 1);
  assert.equal(row.withinSla, 0);
});

test("computeRemediationSla excludes Info-severity findings from the SLA clock entirely", () => {
  // 400 days old -- older than even the old hardcoded Info threshold
  // (365 days) -- but Info has no SLA clock (see findingSlaInfo), so this
  // must not count toward open/breach/within/due, even though the company
  // still appears (it has a remediation finding, just not an SLA-scoped one).
  fixture([baseFinding({ id: "VLN-1", severity: "Info", firstSeen: daysAgo(400) })]);
  const result = store.computeRemediationSla();
  const row = result.clients.find((c) => c.companyId === company.id);
  assert.ok(row, "the company still appears, since it has a remediation finding");
  assert.equal(row.open, 0);
  assert.equal(row.breached, 0);
});

test("computeRemediationSla's slaPolicy reflects the configured thresholds and never includes Info", () => {
  fixture([]);
  const result = store.computeRemediationSla();
  const bySeverity = Object.fromEntries(result.slaPolicy.map((p) => [p.severity, p.days]));
  assert.deepEqual(bySeverity, CUSTOM_SLA);
  assert.ok(!("Info" in bySeverity));
});

test("computeMetrics's slaBuckets uses the configured Settings > SLA and excludes Info", () => {
  fixture([
    baseFinding({ id: "VLN-1", severity: "High", firstSeen: daysAgo(6) }), // breached at High=5
    baseFinding({ id: "VLN-2", severity: "Info", firstSeen: daysAgo(400) }), // excluded entirely
  ]);
  const metrics = store.computeMetrics({ companyId: company.id });
  const breached = metrics.slaBuckets.find((b) => b.breach);
  assert.equal(breached.count, 1, "only the High finding should count toward the breached bucket");
  const totalBucketed = metrics.slaBuckets.reduce((sum, b) => sum + b.count, 0);
  assert.equal(totalBucketed, 1, "the Info finding must not land in any bucket");
});

test("computeMetrics's composite slaBreach component respects the configured Settings > SLA", () => {
  fixture([baseFinding({ id: "VLN-1", severity: "High", firstSeen: daysAgo(6) })]);
  const metrics = store.computeMetrics({ companyId: company.id });
  assert.equal(metrics.composite.components.slaBreach, 100, "the sole open finding breaches the configured 5-day High threshold");
});
