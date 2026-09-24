// Run with: node --experimental-vm-modules --test tests/elastic-dashboard.test.mjs
// Optional database integration: ELASTIC_TEST_DATABASE_URL must point to the
// disposable local database created for these tests, never a production DB.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import ts from "typescript";
import pg from "pg";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const modules = new Map();
const overrides = new Map();
async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const source = await readFile(path, "utf8");
  const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const module = new SourceTextModule(js, { identifier: path });
  modules.set(path, module);
  await module.link(async (specifier) => {
    if (specifier === "@/lib/elastic-dashboard") return load("lib/elastic-dashboard.ts");
    if (overrides.has(specifier)) {
      const values = overrides.get(specifier);
      return new SyntheticModule(Object.keys(values), function () { for (const [key, value] of Object.entries(values)) this.setExport(key, value); });
    }
    if (specifier.startsWith(".")) return load(resolve(dirname(path), `${specifier}.ts`));
    const values = await import(specifier);
    return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return module;
}
const contractModule = await load("lib/elastic-dashboard.ts");
await contractModule.evaluate();
const contract = contractModule.namespace;
const clientModule = await load("lib/elastic-query-client.ts");
await clientModule.evaluate();
const client = clientModule.namespace;
process.env.NEXTAUTH_SECRET = randomBytes(32).toString("hex");
const numeric = { columns: [{ name: "managed", type: "long" }, { name: "coverage_pct", type: "double" }], rows: [[120, 80]], truncated: false };

test("queries retain the original ES|QL and reject invalid definitions", async () => {
  const parsed = contract.parseDefinition(contract.DEFAULT_COVERAGE, "asset-coverage");
  assert.match(parsed.query, /FROM logs-crowdstrike\.discover_asset-\*/);
  assert.equal(parsed.query, (await readFile("n8n/elastic/asset-coverage.esql", "utf8")).replace(/\r\n/g, "\n").trim());
  assert.throws(() => contract.parseDefinition({ ...parsed, refreshMinutes: 0 }, parsed.id));
  assert.throws(() => contract.parseDefinition({ ...parsed, query: "x".repeat(16001) }, parsed.id));
  assert.throws(() => contract.parseDefinition({ ...parsed, title: "" }, parsed.id));
});
test("result parsing supports numeric summaries, nulls, and bounded tables", () => {
  const summary = contract.parseQueryResult({ columns: numeric.columns, values: [[120, null]] });
  assert.equal(contract.canShowMetrics(summary), true);
  const table = contract.parseQueryResult({ columns: [{ name: "host", type: "keyword" }], values: Array.from({ length: 101 }, (_, i) => [`host-${i}`]) });
  assert.equal(table.rows.length, 100);
  assert.equal(table.truncated, true);
  assert.equal(contract.canShowMetrics(table), false);
  assert.throws(() => contract.parseQueryResult({ columns: numeric.columns, values: [[120, 80]], is_partial: true }));
  assert.throws(() => contract.parseQueryResult({ columns: numeric.columns, values: [[120, 80]] }, true));
  assert.throws(() => contract.parseQueryResult({ columns: numeric.columns, values: [[NaN, 80]] }));
});

test("chart definitions preserve mappings and validate real result shapes", () => {
  const result = { columns: [{ name: "tier", type: "keyword" }, { name: "findings", type: "long" }], rows: [["P1", 8], ["P2", 12], ["P3", null]], truncated: false };
  const chart = { category: "tier", value: "findings" };
  assert.deepEqual(contract.suggestChart(result), chart);
  for (const display of ["bar", "line", "doughnut"]) {
    const definition = contract.parseDefinition({ ...contract.DEFAULT_COVERAGE, display, chart }, "chart-test");
    assert.deepEqual(definition.chart, chart);
    contract.validateDisplayResult(result, definition);
    assert.equal(contract.chartData(result, definition).points[2].value, null, "Missing values must not become zero");
    assert.throws(() => contract.parseDefinition({ ...definition, chart: undefined }, "chart-test"));
    assert.throws(() => contract.chartData({ ...result, rows: [["P1", 8], ["P1", 2]] }, definition), /one row per category/);
    assert.throws(() => contract.chartData({ ...result, columns: [result.columns[0]] }, definition), /missing/);
  }
  const negative = { ...result, rows: [["P1", -8], ["P2", 0]] };
  contract.validateDisplayResult(negative, { display: "bar", chart });
  assert.throws(() => contract.validateDisplayResult(negative, { display: "doughnut", chart }), /non-negative/);
  assert.throws(() => contract.chartData({ ...result, rows: [[null, 8]] }, { display: "bar", chart }), /cannot be null/);
  assert.throws(() => contract.chartData({ ...result, rows: [["P1", "8"]] }, { display: "bar", chart }), /finite numbers/);
  assert.throws(() => contract.chartData(result, { display: "bar", chart: { category: "findings", value: "tier" } }), /must be numeric/);
  contract.validateDisplayResult({ ...result, rows: [] }, { display: "bar", chart });
  assert.equal(contract.parseDefinition(contract.DEFAULT_COVERAGE, "asset-coverage").chart, undefined);
});

test("line charts sort and retain real time coordinates and missing points", () => {
  const result = { columns: [{ name: "time", type: "date" }, { name: "count", type: "long" }],
    rows: [["2026-09-24T03:00:00Z", 8], ["2026-09-24T00:00:00Z", 2], ["2026-09-24T01:00:00Z", null]], truncated: false };
  const data = contract.chartData(result, { display: "line", chart: { category: "time", value: "count" } });
  assert.equal(data.scale, "time");
  assert.deepEqual(data.points.map((p) => p.value), [2, null, 8]);
  assert.equal(data.points[2].x - data.points[1].x, 7200000);
});

test("native charts render valid SVG, accessible data, and explicit empty states", async () => {
  const module = await load("components/ElasticResultChart.tsx");
  await module.evaluate();
  const chart = { category: "tier", value: "count" };
  const base = { columns: [{ name: "tier", type: "keyword" }, { name: "count", type: "long" }], rows: [["P1", 8], ["P2", 12]], truncated: false };
  const render = (display, result = base) => renderToStaticMarkup(createElement(module.namespace.default, { result, definition: { display, chart } }));
  for (const display of ["bar", "line", "doughnut"]) {
    const html = render(display);
    assert.match(html, /<svg/);
    assert.match(html, /View chart data/);
    assert.match(html, /role="img"/);
    assert.doesNotMatch(html, /NaN|Infinity/);
    assert.match(render(display, { ...base, rows: [] }), /returned no rows/);
    assert.match(render(display, { ...base, rows: [["P1", null]] }), /No numeric values/);
    assert.match(render(display, { ...base, truncated: true }), /Partial chart/);
    assert.doesNotMatch(render(display, { ...base, rows: [["P1", 8]] }), /NaN|Infinity/);
  }
  assert.match(render("doughnut", { ...base, rows: [["P1", 0]] }), /All values are zero/);
  assert.match(render("doughnut", { ...base, rows: [["P1", -2]] }), /non-negative/);
  assert.doesNotMatch(render("bar", { ...base, rows: [["P1", -2], ["P2", 0], ["P3", 8]] }), /NaN|Infinity/);
  const gaps = render("line", { ...base, rows: [["P1", 2], ["P2", null], ["P3", 8]] });
  assert.match(gaps, /d="M[^"]* M/);
});
test("only public HTTPS endpoints are supported; internal addresses are blocked", () => {
  for (const endpoint of ["http://example.com", "https://user:key@example.com", "https://localhost", "https://example.com?key=x", "https://deployment.kb.region.aws.found.io"]) {
    assert.throws(() => client.normalizeEndpoint(endpoint));
  }
  for (const ip of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1"]) assert.equal(client.isPublicIPv4(ip), false);
  assert.equal(client.isPublicIPv4("8.8.8.8"), true);
});
test("saved API keys are authenticated-encrypted, with tamper detection", () => {
  const connection = { endpoint: "https://elastic.example.com", apiKey: "private-test-key" };
  const sealed = client.sealConnection(connection);
  assert.equal(sealed.includes(connection.apiKey), false);
  assert.deepEqual(client.openConnection(sealed), connection);
  const parts = sealed.split(".");
  parts[3] = Buffer.from("tampered").toString("base64");
  assert.throws(() => client.openConnection(parts.join(".")));
});

test("HTTP client rejects metadata and loopback endpoints before sending a key", async () => {
  for (const endpoint of ["https://127.0.0.1", "https://169.254.169.254"]) {
    await assert.rejects(() => client.executeEsql({ endpoint, apiKey: "never-sent-test-key" }, "ROW x = 1"), /public Elasticsearch/);
  }
});

test("Postgres integration: persistence, source isolation, stale-result retention and edit races", { skip: !process.env.ELASTIC_TEST_DATABASE_URL }, async () => {
  const url = new URL(process.env.ELASTIC_TEST_DATABASE_URL);
  assert.ok(["127.0.0.1", "localhost"].includes(url.hostname) && url.pathname === "/elastic_test", "Use the disposable local elastic_test database.");
  process.env.ELASTIC_VULN_DATABASE_URL = url.toString();
  const db = new pg.Pool({ connectionString: url.toString() });
  let response = numeric;
  let fail = false;
  let hold = null;
  overrides.set("./persist", { applicationDatabase: () => null });
  overrides.set("./elastic-vuln-server", { elasticVulnEnabled: () => true });
  overrides.set("./elastic-query-client", { ...client,
    executeEsql: async () => {
      if (hold) { const wait = hold; hold = null; return await wait; }
      if (fail) throw new contract.DashboardError("Simulated Elastic outage.");
      return response;
    },
  });
  const storeModule = await load("lib/elastic-dashboard-store.ts");
  await storeModule.evaluate();
  const store = storeModule.namespace;
  async function waitFor(check) {
    for (let n = 0; n < 100; n++) { if (await check()) return; await delay(25); }
    assert.fail("Timed out waiting for refresh.");
  }
  try {
    await db.query("DROP TABLE IF EXISTS elastic_dashboard_audit, elastic_dashboard_queries, elastic_dashboard_connection");
    await db.query("CREATE TABLE IF NOT EXISTS vuln_store (key TEXT PRIMARY KEY, data JSONB); INSERT INTO vuln_store VALUES ('sentinel', '{\"keep\":true}') ON CONFLICT DO NOTHING");
    const first = await store.readDashboard(true);
    assert.equal(first.storageReady, true);
    assert.equal(first.connected, false);
    assert.equal(first.queries.length, 1);
    await store.saveConnection({ endpoint: "https://elastic.example.com", apiKey: "private-test-key" }, "admin-connect");
    await waitFor(async () => (await store.readDashboard(true)).queries[0].result !== null);
    const raw = (await db.query("SELECT secret FROM elastic_dashboard_connection")).rows[0].secret;
    assert.equal(raw.includes("private-test-key"), false);
    const memberView = await store.readDashboard(false);
    assert.equal(memberView.endpoint, undefined);
    assert.equal(JSON.stringify(memberView).includes("private-test-key"), false);
    await assert.rejects(() => store.saveConnection({ endpoint: "https://other.example.com", apiKey: "" }, "admin-other"));
    await store.saveQuery({ ...contract.DEFAULT_COVERAGE, id: "extra", title: "Extra query" }, "admin-extra");
    assert.equal((await store.readDashboard(true)).queries.length, 2);
    const old = (await store.readDashboard(true)).queries.find((q) => q.id === "extra");
    fail = true;
    await db.query("UPDATE elastic_dashboard_queries SET next_attempt = now() - interval '1 hour', attempted_at = now() - interval '1 hour'");
    store.triggerRefresh();
    await waitFor(async () => (await store.readDashboard(true)).queries.every((q) => q.error));
    const failed = (await store.readDashboard(true)).queries.find((q) => q.id === "extra");
    assert.deepEqual(failed.result, old.result);
    assert.equal(failed.refreshedAt, old.refreshedAt);
    fail = false;
    await waitFor(() => !globalThis.__elasticDashboard.ticking);
    let release;
    hold = new Promise((resolve) => { release = resolve; });
    await db.query("UPDATE elastic_dashboard_queries SET next_attempt = now() - interval '1 hour' WHERE id = 'extra'");
    store.triggerRefresh();
    await waitFor(() => hold === null);
    response = { ...numeric, rows: [[999, 90]] };
    await store.saveQuery({ ...contract.DEFAULT_COVERAGE, id: "extra", title: "Edited query" }, "admin-edit");
    release(numeric);
    await waitFor(() => !globalThis.__elasticDashboard.ticking);
    const edited = (await store.readDashboard(true)).queries.find((q) => q.id === "extra");
    assert.equal(edited.result.rows[0][0], 999, "Old in-flight results cannot overwrite an edit.");
    const chartResult = { columns: [{ name: "tier", type: "keyword" }, { name: "findings", type: "long" }], rows: [["P1", 8], ["P2", 12]], truncated: false };
    response = chartResult;
    const chartDefinition = { ...contract.DEFAULT_COVERAGE, id: "priority-chart", display: "bar", chart: { category: "tier", value: "findings" } };
    await store.saveQuery(chartDefinition, "chart-member");
    assert.deepEqual((await store.readDashboard(true)).queries.find((q) => q.id === "priority-chart").chart, chartDefinition.chart);
    response = numeric;
    await db.query("UPDATE elastic_dashboard_queries SET next_attempt = now() - interval '1 hour' WHERE id = 'priority-chart'");
    store.triggerRefresh();
    await waitFor(async () => Boolean((await store.readDashboard(true)).queries.find((q) => q.id === "priority-chart").error));
    const retainedChart = (await store.readDashboard(true)).queries.find((q) => q.id === "priority-chart");
    assert.deepEqual(retainedChart.result, chartResult, "A changed result schema must retain the last valid chart");
    assert.match(retainedChart.error, /missing/);
    await waitFor(() => !globalThis.__elasticDashboard.ticking);
    assert.deepEqual((await db.query("SELECT data FROM vuln_store WHERE key = 'sentinel'")).rows[0].data, { keep: true });
    const oldSecret = process.env.NEXTAUTH_SECRET;
    process.env.NEXTAUTH_SECRET = randomBytes(32).toString("hex");
    assert.equal((await store.readDashboard(true)).storageReady, true, "Reconnect must remain available after secret rotation.");
    process.env.NEXTAUTH_SECRET = oldSecret;
    // Leave the isolated DB unconnected for the subsequent HTTP authorization checks.
    await db.query("DELETE FROM elastic_dashboard_connection");
  } finally { await db.end(); }
});
