// node --experimental-vm-modules --test tests/finding-correlation.test.mjs
//
// Exercises the cross-connector correlation logic in lib/store.ts: the same
// (company, CVE, asset) reported by more than one scanner must merge into
// one finding — never duplicated, never silently dropped, never merged
// across companies. This is the exact behavior a real MSSP customer's data
// depends on for correct severity counts and non-duplicated patch tickets.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const ROOT = resolve(".");
const modules = new Map();
async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const source = await readFile(path, "utf8");
  if (modules.has(path)) return modules.get(path);
  const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const module = new SourceTextModule(code, { identifier: path }); modules.set(path, module);
  await module.link(async (name) => {
    if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
    if (name.startsWith("@/")) return load(resolve(ROOT, `${name.slice(2)}.ts`));
    const values = await import(name);
    return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return module;
}
const storeModule = await load("lib/store.ts");
await storeModule.evaluate();
const store = storeModule.namespace;

// A minimal StoreShape fixture — only the maps the correlation functions
// (and the risk-scoring they trigger through rescoreFinding) actually read.
function fixtureStore() {
  return { companies: new Map(), findings: new Map(), assets: new Map(), compensatingControls: new Map(), identityAliases: new Map() };
}
function baseFinding(overrides = {}) {
  return {
    id: overrides.id ?? "VLN-1", companyId: "company-a", companyName: "Company A",
    connector: "nessus", cve: "CVE-2026-1000", title: "Test finding", severity: "Medium",
    cvss: 5, cvssV2: 0, cvssV3: 5, vpr: 0, epss: 0, asset: "server-1", port: "N/A",
    category: "Test", description: "", remediation: "", status: "Open", assignee: null,
    firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-01T00:00:00Z", resolvedAt: null,
    exploitAvailable: false, kev: false, ransomware: false,
    assetExposure: "Internal", assetCriticality: "Normal", assetSource: "inferred",
    realRisk: 0, riskPriority: "Low",
    ...overrides,
  };
}

test("correlationKey scopes by company and normalizes the asset string", () => {
  const s = fixtureStore();
  const a = store.correlationKey(s, "company-a", "CVE-2026-1", "Server-1.corp.local.");
  const b = store.correlationKey(s, "company-a", "cve-2026-1", "  server-1.corp.local");
  const differentCompany = store.correlationKey(s, "company-b", "CVE-2026-1", "server-1.corp.local");
  assert.equal(a, b, "case, whitespace, and a trailing dot must not affect the key");
  assert.notEqual(a, differentCompany, "the same asset+CVE string must never collide across companies");
});

test("linkIdentities unions identifiers, company-scoped, so either resolves the same", () => {
  const s = fixtureStore();
  store.linkIdentities(s, "company-a", ["server-1.corp.local", "10.0.0.5", "203.0.113.9"]);
  const byHostname = store.resolveIdentity(s, "company-a", "server-1.corp.local");
  const byInternalIp = store.resolveIdentity(s, "company-a", "10.0.0.5");
  const byExternalIp = store.resolveIdentity(s, "company-a", "203.0.113.9");
  assert.equal(byHostname, byInternalIp, "internal IP must resolve to the same identity as the hostname it was linked with");
  assert.equal(byHostname, byExternalIp, "external IP must resolve to the same identity as the hostname it was linked with");

  // The exact scenario this was built for: an external scanner's public IP
  // and an agent's internal hostname must correlate as the same device.
  const cveDevices = store.correlationKey(s, "company-a", "CVE-2026-1", "server-1.corp.local");
  const cveExternal = store.correlationKey(s, "company-a", "CVE-2026-1", "203.0.113.9");
  assert.equal(cveDevices, cveExternal, "an external IP and an internal hostname linked to the same device must produce the same correlation key");

  // Company segmentation: the same raw IP string in a different company must
  // never be pulled into company-a's identity group.
  const otherCompanySameIp = store.resolveIdentity(s, "company-b", "203.0.113.9");
  assert.notEqual(byExternalIp, otherCompanySameIp, "identifiers must never link across companies even when the raw string is identical");
});

test("linkIdentities is a safe no-op for fewer than two real identifiers", () => {
  const s = fixtureStore();
  store.linkIdentities(s, "company-a", []);
  store.linkIdentities(s, "company-a", ["only-one"]);
  store.linkIdentities(s, "company-a", ["", null, undefined, "only-one"]);
  assert.equal(s.identityAliases.size, 0, "linking should not record anything when there's nothing to union");
});

test("buildCorrelationIndex only includes open findings from correlated connectors", () => {
  const s = fixtureStore();
  const nessusOpen = baseFinding({ id: "VLN-1", connector: "nessus", cve: "CVE-2026-1", asset: "server-1" });
  const crowdstrikeResolved = baseFinding({ id: "VLN-2", connector: "crowdstrike", cve: "CVE-2026-2", asset: "server-2", status: "Resolved" });
  const burpOpen = baseFinding({ id: "VLN-3", connector: "burp", cve: "CVE-2026-3", asset: "server-3" });
  for (const f of [nessusOpen, crowdstrikeResolved, burpOpen]) s.findings.set(f.id, f);

  const index = store.buildCorrelationIndex(s);
  assert.equal(index.size, 1, "only the open finding from a correlated connector should be indexed");
  assert.equal(index.get(store.correlationKey(s, "company-a", "CVE-2026-1", "server-1")), nessusOpen);
  assert.ok(!index.has(store.correlationKey(s, "company-a", "CVE-2026-2", "server-2")), "resolved findings must not be correlation candidates");
  assert.ok(!index.has(store.correlationKey(s, "company-a", "CVE-2026-3", "server-3")), "Burp is a scanner-specific test result, not a host+CVE fact, and must stay out of correlation");
});

test("correlateFinding merges a corroborating scanner instead of duplicating", () => {
  const s = fixtureStore();
  const existing = baseFinding({
    id: "VLN-1", connector: "nessus", severity: "Medium", cvss: 5, cvssV3: 5, cvssV2: 0,
    vpr: 0, epss: 0.1, exploitAvailable: false, lastSeen: "2026-01-01T00:00:00Z",
  });
  s.findings.set(existing.id, existing);

  store.correlateFinding(s, existing, {
    connector: "crowdstrike", cvss: 9.8, cvssV3: 9.8, cvssV2: 0, vpr: 0, epss: 0.6,
    exploitAvailable: true, severity: "Critical", lastSeen: "2026-02-01T00:00:00Z",
  });

  assert.deepEqual([...existing.seenBy].sort(), ["crowdstrike", "nessus"], "both the original and corroborating connector must be recorded");
  assert.equal(existing.severity, "Critical", "the more severe of the two assessments must win");
  assert.equal(existing.cvss, 9.8);
  assert.equal(existing.cvssV3, 9.8);
  assert.equal(existing.epss, 0.6, "the higher EPSS score must win");
  assert.equal(existing.exploitAvailable, true, "exploit-available from either scanner must stick");
  assert.equal(existing.lastSeen, "2026-02-01T00:00:00Z");
  assert.ok(existing.realRisk > 0, "merging must re-derive the real-risk score, not leave the pre-merge value in place");

  // A second, weaker report must not walk severity/cvss back down.
  store.correlateFinding(s, existing, {
    connector: "defender", cvss: 4, cvssV3: 4, cvssV2: 0, vpr: 0, epss: 0.01,
    exploitAvailable: false, severity: "Low", lastSeen: "2026-03-01T00:00:00Z",
  });
  assert.equal(existing.severity, "Critical", "a weaker corroborating report must never downgrade an already-confirmed severity");
  assert.equal(existing.cvss, 9.8);
  assert.equal(existing.epss, 0.6);
  assert.deepEqual([...existing.seenBy].sort(), ["crowdstrike", "defender", "nessus"]);
  assert.equal(existing.lastSeen, "2026-03-01T00:00:00Z", "lastSeen always advances to the most recent report");
});

test("canonicalAssetKey prefers the asset inventory over the self-learned alias graph", () => {
  const s = fixtureStore();
  s.assets.set("AST-1", { id: "AST-1", identifier: "server-1", hostname: "server-1.corp.local", ipAddresses: ["10.0.0.9"], companyId: "company-a" });
  const viaInventory = store.canonicalAssetKey(s, "company-a", "server-1.corp.local");
  assert.equal(viaInventory, "asset:AST-1", "a known inventory asset must resolve to its stable id, not a raw-string or alias key");

  store.linkIdentities(s, "company-a", ["server-1.corp.local", "203.0.113.50"]);
  const stillViaInventory = store.canonicalAssetKey(s, "company-a", "203.0.113.50");
  // The alias graph links this IP to the hostname, but the hostname itself
  // resolves through the inventory — canonicalAssetKey only consults the
  // alias graph for the string it was given directly, so an IP with no
  // inventory entry of its own falls back to its own alias-group key.
  assert.notEqual(stillViaInventory, "asset:AST-1");
  assert.equal(stillViaInventory, `alias:${store.resolveIdentity(s, "company-a", "203.0.113.50")}`);
});
