// node --experimental-vm-modules tests/vulners-bridge-targets.test.mjs
//
// Exercises nessusBridgeTargetsForCompany (lib/store.ts): the Vulners
// Bridge's "ported from Nessus" target list. Deriving targets from
// Finding.asset alone misses every host Nessus scanned clean -- a bridge
// scan only ever widens as findings close, never as new hosts come under
// management, understating coverage for companies with mostly-healthy
// estates. scannedHostAliases (persisted per completed Nessus scan import)
// fixes that; this confirms both sources are unioned correctly, and that
// older scans recorded before that field existed still fall back cleanly.
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

const company = { id: "CO-TEST", name: "Example Customer", kind: "client", industry: "Test", createdAt: "2026-10-01T00:00:00Z", contactName: "", contactEmail: "" };

function fixture() {
  return {
    companies: new Map([[company.id, company]]), folders: new Map(), scans: new Map(), findings: new Map(), assets: new Map(),
    compensatingControls: new Map(), identityAliases: new Map(),
    settings: { autoScanNewAssets: false, schedule: { autoSyncEnabled: false, alertsEnabled: false, monthlyReportsEnabled: false, autoSyncIntervalHours: 24 }, sla: { Critical: 7, High: 30, Medium: 60, Low: 90 } },
    meta: { defenderGenerations: {}, nessusOffsetLastTriggered: {} }, seeded: true, counter: 1000,
  };
}

function nessusFinding(overrides = {}) {
  return {
    id: overrides.id ?? "VLN-1", scanId: "SCAN-1", companyId: company.id, companyName: company.name,
    connector: "nessus", cve: "CVE-2026-1000", title: "Test finding", severity: "Medium",
    cvss: 5, cvssV2: 0, cvssV3: 5, vpr: 0, epss: 0, asset: "host-with-finding", port: "N/A",
    category: "Test", description: "", remediation: "", status: "Open", assignee: null,
    firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-01T00:00:00Z", resolvedAt: null,
    exploitAvailable: false, kev: false, ransomware: false,
    assetExposure: "Internal", assetCriticality: "Normal", assetSource: "inferred",
    realRisk: 0, riskPriority: "Low",
    ...overrides,
  };
}

function nessusScan(overrides = {}) {
  return {
    id: "SCAN-1", name: "Nessus scan", companyId: company.id, companyName: company.name,
    folderId: "FOLD-1", folderName: "Nessus", connector: "nessus", profile: "basic",
    targets: [], status: "Completed", progress: 100, createdAt: "2026-01-01T00:00:00Z",
    startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:05:00Z",
    findingsCount: 1, severityCounts: { Critical: 0, High: 0, Medium: 1, Low: 0, Info: 0 },
    hostsScanned: 2, requestedBy: "test",
    ...overrides,
  };
}

test("nessusBridgeTargetsForCompany includes hosts Nessus scanned clean, not just hosts with findings", () => {
  const s = fixture();
  s.findings.set("VLN-1", nessusFinding());
  s.scans.set("SCAN-1", nessusScan({ scannedHostAliases: ["host-with-finding", "host-clean"] }));
  globalThis.__vulnStore = s;
  const targets = store.nessusBridgeTargetsForCompany(company.id);
  assert.deepEqual(new Set(targets), new Set(["host-with-finding", "host-clean"]));
});

test("nessusBridgeTargetsForCompany falls back to Finding.asset for a scan recorded before scannedHostAliases existed", () => {
  const s = fixture();
  s.findings.set("VLN-1", nessusFinding({ asset: "legacy-host" }));
  s.scans.set("SCAN-1", nessusScan()); // no scannedHostAliases field at all
  globalThis.__vulnStore = s;
  const targets = store.nessusBridgeTargetsForCompany(company.id);
  assert.deepEqual(targets, ["legacy-host"]);
});

test("nessusBridgeTargetsForCompany never crosses companies", () => {
  const s = fixture();
  s.companies.set("CO-OTHER", { ...company, id: "CO-OTHER" });
  s.scans.set("SCAN-2", nessusScan({ id: "SCAN-2", companyId: "CO-OTHER", scannedHostAliases: ["other-host"] }));
  s.scans.set("SCAN-1", nessusScan({ scannedHostAliases: ["own-host"] }));
  globalThis.__vulnStore = s;
  assert.deepEqual(store.nessusBridgeTargetsForCompany(company.id), ["own-host"]);
  assert.deepEqual(store.nessusBridgeTargetsForCompany("CO-OTHER"), ["other-host"]);
});

test("nessusBridgeTargetsForCompany ignores a non-Nessus scan's host list", () => {
  const s = fixture();
  s.scans.set("SCAN-1", nessusScan({ connector: "vulners", scannedHostAliases: ["should-not-appear"] }));
  globalThis.__vulnStore = s;
  assert.deepEqual(store.nessusBridgeTargetsForCompany(company.id), []);
});
