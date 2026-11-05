// node --experimental-vm-modules --test tests/approved-scanner-target-parity.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";
import { SourceTextModule, SyntheticModule } from "node:vm";

const source = await readFile("lib/approved-scanner-target-parity.ts", "utf8");
const js = ts.transpileModule(source, { compilerOptions: {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
}}).outputText;
const key = value => {
  if (typeof value !== "string" || !value || value !== value.trim() ||
      /[*/]/.test(value) || /:\/\//.test(value)) throw Error("not an exact host");
  return value.toLowerCase().replace(/\.$/, "");
};
const targetMatcher = targets => {
  if (targets.length !== 1 || typeof targets[0] !== "string" ||
      !/^(?:[0-9.]+|[0-9a-f:]+)\/(?:[0-9]|[12][0-9]|3[0-2]|[3-9][0-9]|1[0-2][0-8])$/i.test(targets[0]))
    throw Error("invalid network");
  return () => false;
};
const module = new SourceTextModule(js);
await module.link(async spec => {
  assert.equal(spec, "./scanner-target-scope");
  return new SyntheticModule(["scannerExactTargetKey", "scannerTargetMatcher"], function () {
    this.setExport("scannerExactTargetKey", key);
    this.setExport("scannerTargetMatcher", targetMatcher);
  });
});
await module.evaluate();
const { compareApprovedScannerTargets: compare } = module.namespace;
const nessus = (targets, companyId="CO-A") => ({ provider: "nessus", companyId, sourceScope: "7", targets });
const bridge = (targets, companyId="CO-A") => ({ provider: "vulners", companyId, targets });

test("same approved exact scopes match, but never claim scan execution parity", () => {
  const result = compare([nessus(["HOST.EXAMPLE.", "10.0.0.2"])], [bridge(["10.0.0.2", "host.example"])]);
  assert.equal(result.mode, "approved-scopes-only");
  assert.equal(result.executedScanParityVerified, false);
  assert.equal(result.matchedApprovedScopeCount, 1);
  assert.equal(result.companies[0].status, "approved-targets-match");
  assert.equal(result.companies[0].matchingExactCount, 2);
  assert.equal(result.companies[0].nessusFolderId, "7");
});

test("shows missing and unexpected targets within the right customer", () => {
  const result = compare([nessus(["a.example", "b.example"])], [bridge(["a.example", "c.example"])]);
  assert.equal(result.companies[0].status, "approved-targets-differ");
  assert.deepEqual([...result.companies[0].missingFromVulners], ["b.example"]);
  assert.deepEqual([...result.companies[0].notExactNessusTargets], ["c.example"]);
});

test("CIDRs cannot be declared equivalent to a partial list of Greenbone hosts", () => {
  const result = compare([nessus(["10.0.0.0/24"])], [bridge(["10.0.0.2"])]);
  assert.equal(result.companies[0].status, "unverifiable");
  assert.deepEqual([...result.companies[0].nessusNetworksRequiringExpansionReview], ["10.0.0.0/24"]);
  assert.equal(result.matchedApprovedScopeCount, 0);
});

test("disabled reviewed routing is a global unknown, not a clean empty estate", () => {
  for (const [a, b] of [[null, []], [[], null]]) {
    const result = compare(a, b);
    assert.equal(result.executedScanParityVerified, false);
    assert.equal(result.unresolvedCompanyCount, 1);
    assert.equal(result.matchedApprovedScopeCount, 0);
  }
});

test("missing source review or duplicate targets cannot pass", () => {
  const missing = compare([], [bridge(["a.example"])]);
  assert.equal(missing.companies[0].status, "unverifiable");
  const duplicate = compare([nessus(["A.example", "a.example"])], [bridge(["a.example"])]);
  assert.equal(duplicate.companies[0].status, "unverifiable");
});

test("different customer IDs never satisfy each other's scope", () => {
  const result = compare([nessus(["a.example"])], [bridge(["a.example"], "CO-B")]);
  assert.equal(result.matchedApprovedScopeCount, 0);
  assert.equal(result.unresolvedCompanyCount, 2);
});

test("admin endpoint is gated and read-only", async () => {
  const route = await readFile("app/api/admin/scanner-target-parity/route.ts", "utf8");
  assert.match(route, /adminTokenOk\(request\)/);
  assert.match(route, /loadReviewedScannerRoutes\("nessus"\)/);
  assert.match(route, /loadReviewedScannerRoutes\("vulners"\)/);
  assert.doesNotMatch(route, /export (?:async )?function POST|vulnersBridgeStartScan|startScan/);
});
