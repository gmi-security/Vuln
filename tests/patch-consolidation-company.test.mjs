// node --experimental-vm-modules --test tests/patch-consolidation-company.test.mjs
//
// The consolidation review queue only ever showed a prepared plan under a
// customer whose CrowdStrike tenant happened to be on the Atlas-only
// allowlist — every other customer's plans had nowhere to land. These cover
// the fix: an analyst's explicit customer selection at build time is
// validated and carried straight onto every resulting patch group, with no
// dependency on inferring ownership from the CrowdStrike tenant.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const ROOT = resolve(".");
const modules = new Map();
const companies = new Map([
  ["CO-1", { id: "CO-1", name: "Atlas Healthcare Partners", kind: "client", isDemo: false }],
  ["CO-2", { id: "CO-2", name: "SplashWorks", kind: "client", isDemo: true }],
  ["CO-3", { id: "CO-3", name: "GMI", kind: "internal", isDemo: false }],
]);

async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const source = await readFile(path, "utf8");
  if (modules.has(path)) return modules.get(path);
  const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const module = new SourceTextModule(code, { identifier: path }); modules.set(path, module);
  await module.link(async (name) => {
    if (name === "./store" || name === "@/lib/store") {
      const values = { getCompany: (id) => companies.get(id) };
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    }
    if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
    if (name.startsWith("@/")) return load(resolve(ROOT, `${name.slice(2)}.ts`));
    const values = await import(name);
    return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return module;
}
const patchRequestModule = await load("lib/patch-request.ts");
await patchRequestModule.evaluate();
const patchRequest = patchRequestModule.namespace;

test("parseConsolidationInput carries a verified customer's appCompanyId and name", () => {
  const result = patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"], appCompanyId: "CO-1" });
  assert.equal(result.appCompanyId, "CO-1");
  assert.equal(result.companyName, "Atlas Healthcare Partners");
});

test("parseConsolidationInput rejects a demo company and an unknown id, but allows GMI's own internal estate", () => {
  assert.throws(() => patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"], appCompanyId: "CO-2" }), /not found/i);
  assert.throws(() => patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"], appCompanyId: "CO-999" }), /not found/i);
  assert.throws(() => patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"], appCompanyId: "not-a-company-id" }), /valid customer/i);
  // GMI's own estate (kind "internal") is a legitimate consolidation target,
  // not a customer being billed — it just isn't a demo company.
  const result = patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"], appCompanyId: "CO-3" });
  assert.equal(result.appCompanyId, "CO-3");
  assert.equal(result.companyName, "GMI");
});

test("parseConsolidationInput without appCompanyId omits it entirely (backward compatible)", () => {
  const result = patchRequest.parseConsolidationInput({ cves: ["CVE-2026-1000", "CVE-2026-1001"] });
  assert.equal("appCompanyId" in result, false);
});

function finding(overrides = {}) {
  return {
    id: overrides.id ?? "f1", cid: overrides.cid ?? "tenant-a", hostId: overrides.hostId ?? "host-1", hostname: "host-1.corp",
    cve: overrides.cve ?? "CVE-2026-1000", severity: "High", cvss: 7, ip: "10.0.0.1", os: "Windows", hostCriticality: "Normal", exposure: "Internal",
    remediations: [{ id: "r1", title: "Update thing", action: "Install the patch", link: "", vendorUrl: "", reference: "", recommendationType: "recommended", published: "" }],
    apps: [], risk: 50,
    ...overrides,
  };
}

test("buildPatchConsolidation stamps appCompanyId/companyName on every group when a customer was selected", () => {
  const records = [finding()];
  const consolidation = patchRequest.buildPatchConsolidation(["CVE-2026-1000"], records, "us-1", "start", "end", new Set(),
    { appCompanyId: "CO-1", companyName: "Atlas Healthcare Partners" });
  assert.ok(consolidation.groups.length > 0);
  for (const group of consolidation.groups) {
    assert.equal(group.appCompanyId, "CO-1");
    assert.equal(group.companyName, "Atlas Healthcare Partners");
  }
});

test("buildPatchConsolidation omits appCompanyId when no customer was selected", () => {
  const records = [finding()];
  const consolidation = patchRequest.buildPatchConsolidation(["CVE-2026-1000"], records, "us-1", "start", "end");
  assert.ok(consolidation.groups.length > 0);
  for (const group of consolidation.groups) assert.equal("appCompanyId" in group, false);
});

test("buildPatchConsolidation's maxRisk is the highest GMI risk score among a group's devices", () => {
  const records = [
    finding({ id: "f1", hostId: "host-1", hostname: "host-1.corp", risk: 35 }),
    finding({ id: "f2", hostId: "host-2", hostname: "host-2.corp", risk: 88 }),
  ];
  const consolidation = patchRequest.buildPatchConsolidation(["CVE-2026-1000"], records, "us-1", "start", "end");
  assert.ok(consolidation.groups.length > 0);
  for (const group of consolidation.groups) assert.equal(group.maxRisk, 88);
});
