import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/elastic-vuln.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const { parseAssetCoverage } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const workflow = JSON.parse(await readFile(new URL("../n8n/elastic/asset-coverage.workflow.json", import.meta.url), "utf8"));
const normalize = new Function("$json", "$", workflow.nodes.find((node) => node.name === "Validate coverage").parameters.jsCode);
const collectedAt = new Date().toISOString();
const normalizeResult = (body, headers = {}) => normalize({ body, headers }, () => ({ first: () => ({ json: { collectedAt } }) }))[0].json;
const snapshot = (managed, unmanaged, coverage_pct) => ({ queryId: "asset-coverage", collectedAt, results: { managed, unmanaged, coverage_pct } });
const esResponse = { columns: [{ name: "unmanaged" }, { name: "coverage_pct" }, { name: "managed" }], values: [[30, 80, 120]], is_partial: false };

test("ES|QL columns are mapped by name, not position, into the accepted contract", () => {
  assert.deepEqual(parseAssetCoverage(normalizeResult(esResponse)), snapshot(120, 30, 80));
});
test("no assets yields null coverage, not a false zero", () => {
  assert.deepEqual(parseAssetCoverage(snapshot(0, 0, null)), snapshot(0, 0, null));
  assert.throws(() => parseAssetCoverage(snapshot(0, 0, 0)));
});
test("invalid counts, percentages, timestamps and unknown queries are rejected", () => {
  for (const invalid of [snapshot(-1, 1, 0), snapshot(1.5, 1, 60), snapshot(120, 30, 90),
    snapshot(1, 1, null), snapshot("120", 30, 80), snapshot(1, 1, Infinity),
    { ...snapshot(1, 1, 50), queryId: "arbitrary-query" },
    { ...snapshot(1, 1, 50), collectedAt: "2026-01-01" },
    { ...snapshot(1, 1, 50), collectedAt: "2999-01-01T00:00:00Z" }]) {
    assert.throws(() => parseAssetCoverage(invalid));
  }
});
test("rounding and full/zero coverage agree with the query", () => {
  for (const value of [snapshot(1, 2, 33.3), snapshot(2, 1, 66.7), snapshot(1, 0, 100), snapshot(0, 1, 0)]) {
    assert.deepEqual(parseAssetCoverage(value), value);
  }
});
test("warnings, partial results, missing rows and malformed values cannot replace saved data", () => {
  assert.throws(() => normalizeResult(esResponse, { warning: "conversion failed" }));
  for (const response of [{ ...esResponse, is_partial: true }, { ...esResponse, is_running: true },
    { ...esResponse, values: [] }, { ...esResponse, values: [[30, 99, 120]] },
    { ...esResponse, columns: [{ name: "managed" }, { name: "managed" }, { name: "unmanaged" }] }]) {
    assert.throws(() => normalizeResult(response));
  }
});
test("the inactive workflow preserves the supplied query and requests complete results", async () => {
  assert.equal(workflow.active, false);
  const node = workflow.nodes.find((entry) => entry.name === "Query Elasticsearch");
  assert.match(node.parameters.url, /allow_partial_results=false/);
  assert.equal(JSON.parse(node.parameters.jsonBody).query,
    (await readFile(new URL("../n8n/elastic/asset-coverage.esql", import.meta.url), "utf8")).trim());
  assert.equal(workflow.nodes.some((entry) => entry.credentials), false);
});
