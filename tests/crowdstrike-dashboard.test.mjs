// node --experimental-vm-modules --test tests/crowdstrike-dashboard.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import { randomBytes } from "node:crypto";
import test from "node:test";
import ts from "typescript";

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
    const values = await import(name);
    return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return module;
}
const clientModule = await load("lib/crowdstrike-dashboard-client.ts"); await clientModule.evaluate();
const client = clientModule.namespace;
const contract = (await load("lib/elastic-dashboard.ts")).namespace;
const adapter = (await load("lib/crowdstrike-dashboard.ts")).namespace;
const options = { ...contract.DEFAULT_CROWDSTRIKE };
const input = { source: "crowdstrike", query: "status:['open','reopen']", crowdstrike: options };
const connection = { region: "us-2", clientId: "fake-client-id", clientSecret: "fake-client-secret" };
const raw = (id, props = {}) => ({ id, cid: "tenant-a", aid: "host-1", host_info: { hostname: "server" }, status: "open",
  updated_timestamp: "2026-09-24T01:00:00Z", cve: { id: "CVE-2026-1", severity: "HIGH", base_score: 8 }, ...props });
const page = (resources, after = "", total = resources.length) => ({ resources, meta: { pagination: { after, total } } });
async function mockHttp(replies, work) {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (url, init) => {
    if (new URL(url).pathname === "/spotlight/combined/vulnerabilities/v1") {
      assert.deepEqual(new URL(url).searchParams.getAll("facet"), ["cve", "host_info"],
        "CrowdStrike requires repeated facet parameters, not a comma-joined facet");
    }
    calls.push({ url: new URL(url), init });
    const reply = replies.shift(); assert.ok(reply, "Unexpected outbound request");
    return new Response(JSON.stringify(reply.body ?? reply), { status: reply.status ?? 200, headers: reply.headers });
  };
  try { return await work(calls); } finally { globalThis.fetch = original; }
}
const auth = { access_token: "fake-access-token" };

test("connection checks request the same detail facets as saved queries", async () => {
  await mockHttp([auth, page([raw("connection-check")])], async (calls) => {
    await client.testCrowdStrikeConnection(connection);
    assert.equal(calls[1].url.searchParams.get("limit"), "1");
    assert.equal(calls[1].url.searchParams.get("filter"), input.query);
  });
});

test("source contracts reject unsupported datasets and ambiguous history", () => {
  assert.equal(contract.parseQueryInput(input).source, "crowdstrike");
  for (const change of [{ source: "unknown" }, { query: "" }, { query: "x\ny" }, { crowdstrike: { ...options, dataset: "hosts" } },
    { crowdstrike: { ...options, measure: "anything" } }, { crowdstrike: { ...options, history: true, groupBy: "host" } }]) {
    assert.throws(() => contract.parseQueryInput({ ...input, ...change }));
  }
  assert.deepEqual(contract.parseQueryInput({ query: "ROW value = 1" }), { query: "ROW value = 1" });
});

test("CrowdStrike credentials use authenticated encryption and fixed cloud origins", () => {
  process.env.NEXTAUTH_SECRET = randomBytes(32).toString("hex");
  const sealed = client.sealCrowdStrike(connection);
  assert.ok(!sealed.includes(connection.clientSecret));
  assert.deepEqual(client.openCrowdStrike(sealed), connection);
  const parts = sealed.split("."); parts[3] = Buffer.from("tamper").toString("base64");
  assert.throws(() => client.openCrowdStrike(parts.join(".")));
  for (const region of ["https://evil.example", "toString", "__proto__", "localhost"]) {
    assert.throws(() => client.parseCrowdStrikeConnection({ ...connection, region }));
  }
});

test("patch worklist keeps existing contracts and requires a table without history", () => {
  const patch = { ...input, crowdstrike: { ...options, view: "patch-worklist", top: 25 } };
  assert.equal(contract.parseQueryInput(patch).crowdstrike.view, "patch-worklist");
  for (const change of [{ view: "bad" }, { history: true }, { groupBy: "host" }, { measure: "hosts" }]) {
    assert.throws(() => contract.parseQueryInput({ ...patch, crowdstrike: { ...patch.crowdstrike, ...change } }));
  }
  assert.throws(() => contract.parseDefinition({ ...patch, title: "Patch", display: "metrics", refreshMinutes: 1440, enabled: true }, "patch"), /Table/);
});

test("patch worklist ranks across pages, retains device identities and distinguishes findings from hosts", async () => {
  const p1 = { id: "CVE-P1", severity: "LOW", exploit_status: 90 };
  const first = Array.from({ length: 12 }, (_, i) => raw(`medium-${i}`, { aid: `host-${i}` }));
  const second = [raw("p1", { cve: p1 }), raw("p1-other-app", { cve: p1 }),
    raw("p1-other-tenant", { cve: p1, cid: "tenant-b" }),
    raw("p2", { cve: { id: "CVE-P2", severity: "CRITICAL", base_score: 10, exprt_rating: "CRITICAL" } }),
    raw("closed", { cve: p1, status: "closed" }), raw("low", { cve: { severity: "LOW" } })];
  await mockHttp([auth, page(first, "next", first.length + second.length), page(second, "", first.length + second.length)], async (calls) => {
    const result = await client.executeCrowdStrike(connection, { ...input, crowdstrike: { ...options, view: "patch-worklist", top: 10 } });
    const rows = result.rows.map((row) => Object.fromEntries(result.columns.map((column, i) => [column.name, row[i]])));
    assert.equal(calls.length, 3);
    assert.equal(rows.length, 10);
    assert.deepEqual(rows.slice(0, 3).map((row) => row.priority), Array(3).fill("P1 Exploited / KEV"));
    assert.equal(rows[0].affected_devices_for_cve, 2, "Device count deduplicates apps and separates tenants");
    assert.equal(rows[0].host_id, "host-1");
    assert.ok(rows.every((row) => row.finding_id !== "closed" && row.finding_id !== "low"));
    assert.match(result.note, /10 of 16/);
    assert.equal(rows[0].cisa_kev, null, "Absent KEV is unknown, not false");
  });
  assert.deepEqual(adapter.patchWorklist([], 25).rows, []);
  assert.throws(() => adapter.patchWorklist([adapter.normalizeVulnerability(raw("missing-device", { aid: "" }))], 25), /host ID/);
  assert.equal(adapter.vulnerabilityRisk({ exploit_status: 90, is_cisa_kev: true, exprt_rating: "CRITICAL", base_score: 10, exploitability_score: 4, severity: "CRITICAL" }).risk, 100);
});

test("CSV exports quote data and neutralize spreadsheet formulas without changing numeric scores", async () => {
  const module = await load("lib/dashboard-csv.ts"); await module.evaluate();
  const csv = module.namespace.dashboardCsv({ columns: [{ name: "device", type: "keyword" }, { name: "score", type: "double" }],
    rows: [["=cmd()", 90], ['host,"quoted"\nnext', null], [" \t@SUM(A1)", -2]], truncated: false });
  assert.ok(csv.startsWith('\uFEFF"device","score"\r\n'));
  assert.ok(csv.includes('"\'=cmd()","90"'));
  assert.ok(csv.includes('"host,""quoted""\nnext",""'));
  assert.ok(csv.includes('"\' \t@SUM(A1)","-2"'));
});

test("full pagination precedes aggregation; duplicate finding IDs do not inflate counts", async () => {
  await mockHttp([auth, page([raw("a"), raw("b")], "next", 3), page([raw("b"), raw("c", { aid: "host-2", cve: { id: "CVE-2026-2" } })], "", 3)], async (calls) => {
    const result = await client.executeCrowdStrike(connection, input);
    assert.deepEqual(result.rows, [[3]]);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url.origin, "https://api.us-2.crowdstrike.com");
    assert.equal(calls[1].url.searchParams.get("filter"), input.query);
    assert.equal(calls[2].url.searchParams.get("after"), "next");
    assert.ok(calls.every((call) => call.init.redirect === "error"));
    assert.equal(calls[1].init.headers.Authorization, "Bearer fake-access-token");
  });
});

test("counts distinguish CVEs, hosts and tenant-scoped findings; top groups follow full aggregation", () => {
  const records = [raw("a"), raw("b"), raw("a", { cid: "tenant-b" }), raw("c", { aid: "host-2", cve: { id: "CVE-2026-2", severity: "CRITICAL" } })].map(adapter.normalizeVulnerability);
  assert.deepEqual(adapter.summarizeVulnerabilities(records, { ...options, measure: "cves" }).rows, [[2]]);
  assert.deepEqual(adapter.summarizeVulnerabilities(records, { ...options, measure: "hosts" }).rows, [[3]]);
  assert.deepEqual(adapter.summarizeVulnerabilities(records, { ...options, groupBy: "severity" }).rows, [["HIGH", 3], ["CRITICAL", 1]]);
  assert.equal(adapter.summarizeVulnerabilities(records, { ...options, groupBy: "host" }).rows.length, 3);
  assert.throws(() => adapter.summarizeVulnerabilities([adapter.normalizeVulnerability(raw("x", { aid: "" }))], { ...options, measure: "hosts" }), /host ID/);
  assert.deepEqual(adapter.summarizeVulnerabilities([], options).rows, [[0]]);
});

test("GMI priority follows the supplied risk policy and does not treat false strings as KEV", () => {
  assert.equal(adapter.vulnerabilityPriority({ exploit_status: 90 }), "P1 Exploited / KEV");
  assert.equal(adapter.vulnerabilityPriority({ cisa_info: { is_cisa_kev: true } }), "P1 Exploited / KEV");
  assert.equal(adapter.vulnerabilityPriority({ severity: "critical" }), "P2 Critical risk");
  assert.equal(adapter.vulnerabilityPriority({ exprt_rating: "HIGH" }), "P3 High risk");
  assert.equal(adapter.vulnerabilityPriority({ cisa_info: { is_cisa_kev: "false" } }), "Other");
  assert.equal(adapter.vulnerabilityPriority({ exploit_status: 60, base_score: 7 }), "P2 Critical risk");
  assert.equal(adapter.vulnerabilityPriority({ exploit_status: 30, exploitability_score: 3 }), "P3 High risk");
});

test("incomplete pages, cursor loops, page errors and timeouts fail without partial counts", async () => {
  for (const replies of [
    [auth, page([raw("a")], "", 5)],
    [auth, page([raw("a")], "loop", 5), page([raw("b")], "loop", 5)],
    [auth, page([raw("a")], "next", 5), { status: 403, body: { errors: [{ message: "secret" }] } }],
    [auth, { resources: [raw("a")] }],
    [auth, page([{ status: "open" }])],
    [auth, page([raw("a"), raw("a", { status: "closed" })])],
    [auth, { resources: [], meta: { pagination: { total: "not-a-number" } } }],
  ]) await mockHttp(replies, async () => assert.rejects(() => client.executeCrowdStrike(connection, input), contract.DashboardError));
  await mockHttp([], async () => assert.rejects(() => client.executeCrowdStrike(connection, input, -1), /exceeded/));
});

test("rate limits retry with bounded waits; upstream messages redact credentials", async () => {
  await mockHttp([auth, { status: 429, headers: { "retry-after": "0" }, body: {} }, page([])], async (calls) => {
    assert.deepEqual((await client.executeCrowdStrike(connection, input)).rows, [[0]]);
    assert.equal(calls.length, 3);
  });
  await mockHttp([auth, { status: 400, body: { errors: [{ message: "Bad field fake-client-id fake-client-secret Bearer fake-access-token" }] } }], async () => {
    await assert.rejects(() => client.executeCrowdStrike(connection, input), (error) => {
      assert.match(error.message, /Bad field/); assert.doesNotMatch(error.message, /fake-/); return true;
    });
  });
});
