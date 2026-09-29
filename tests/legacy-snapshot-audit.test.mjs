import assert from "node:assert/strict";
import test from "node:test";

test("audit catches duplicate IDs, orphan references and keeps customer totals", async () => {
  const { auditLegacyBuckets } = await import("../lib/db/legacy-snapshot-audit.mjs");
  const buckets = {
    "companies:00": [["CO-1001", { id: "CO-1001", name: "Atlas" }]],
    "folders:00": [["FLD-1002", { id: "FLD-1002", companyId: "CO-1001" }]],
    "scans:00": [["SCAN-1003", { id: "SCAN-1003", companyId: "CO-1001", folderId: "FLD-1002", connector: "crowdstrike", status: "Completed" }]],
    "findings:00": [
      ["VLN-1004", { id: "VLN-1004", companyId: "CO-1001", scanId: "SCAN-1003", connector: "crowdstrike", status: "Open", severity: "High" }],
      ["VLN-1005", { id: "VLN-1005", companyId: "CO-MISSING", scanId: "SCAN-MISSING", connector: "nessus", status: "Open", severity: "Critical" }],
    ],
    "findings:01": [["VLN-1004", { id: "VLN-1004", companyId: "CO-1001", scanId: "SCAN-1003", connector: "crowdstrike", status: "Open", severity: "High" }]],
    "assets:00": [["AST-1006", { id: "AST-1006", companyId: "CO-1001", source: "crowdstrike" }]],
    meta: { counter: 1006, compensatingControls: [], identityAliases: [] },
  };
  const report = await auditLegacyBuckets(Object.entries(buckets).map(([key, data]) => ({ key, data })));
  assert.equal(report.collections.findings.rows, 3);
  assert.equal(report.collections.findings.duplicateIds, 1);
  assert.deepEqual(report.collections.findings.duplicateSamples, ["VLN-1004"]);
  assert.equal(report.orphans.findingCompany.count, 1);
  assert.equal(report.orphans.findingScan.count, 1);
  assert.equal(report.byCompany["CO-1001"].findings, 2);
  assert.equal(report.maxNumericSuffix, 1006);
  assert.equal(report.legacyCounter, 1006);
});

test("audit rejects malformed tuples without losing the rest of the bucket", async () => {
  const { auditLegacyBuckets } = await import("../lib/db/legacy-snapshot-audit.mjs");
  const report = await auditLegacyBuckets([
    { key: "companies:00", data: [["CO-1", { id: "CO-2" }], ["CO-3", { id: "CO-3" }], { id: "CO-4" }] },
    { key: "meta", data: {} },
  ]);
  assert.equal(report.collections.companies.rows, 1);
  assert.equal(report.collections.companies.malformed, 2);
  assert.equal(report.byCompany["CO-3"].companies, 1);
});

test("audit treats unusual source labels as data keys", async () => {
  const { auditLegacyBuckets } = await import("../lib/db/legacy-snapshot-audit.mjs");
  const report = await auditLegacyBuckets([
    { key: "findings:00", data: [["VLN-1", { id: "VLN-1", companyId: "__proto__", scanId: "SCAN-1", connector: "__proto__" }]] },
  ]);
  assert.equal(report.byCompany["__proto__"].findings, 1);
  assert.equal(report.facets.findingConnector["__proto__"], 1);
});

test("identity aliases do not inflate the public ID counter check", async () => {
  const { auditLegacyBuckets } = await import("../lib/db/legacy-snapshot-audit.mjs");
  const report = await auditLegacyBuckets([
    { key: "companies:00", data: [["CO-42", { id: "CO-42" }]] },
    { key: "meta", data: { counter: 42, identityAliases: [["CO-42::host-999999", "host-1"]] } },
  ]);
  assert.equal(report.maxNumericSuffix, 42);
});
