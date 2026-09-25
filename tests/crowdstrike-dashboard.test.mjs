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
      const facets = new URL(url).searchParams.getAll("facet");
      assert.ok(JSON.stringify(facets) === '["cve","host_info"]' || JSON.stringify(facets) === '["cve"]' || JSON.stringify(facets) === '["cve","host_info","remediation"]',
        "CrowdStrike requires separate facet parameters; CVE summaries omit host detail");
    }
    calls.push({ url: new URL(url), init });
    const reply = replies.shift(); assert.ok(reply, "Unexpected outbound request");
    return new Response(JSON.stringify(reply.body ?? reply), { status: reply.status ?? 200, headers: reply.headers });
  };
  try { return await work(calls); } finally { globalThis.fetch = original; }
}
const auth = { access_token: "fake-access-token" };

const cveOptions = { ...options, view: "cve-devices", measure: "hosts", groupBy: "cve", top: 10 };
test("a transient GET failure retries the same page without restarting collection", async () => {
  const original = globalThis.fetch, calls = [];
  let nextPageAttempts = 0;
  globalThis.fetch = async (url) => {
    const parsed = new URL(url); calls.push(parsed);
    if (parsed.pathname === "/oauth2/token") return new Response(JSON.stringify(auth));
    if (!parsed.searchParams.has("after")) return new Response(JSON.stringify(page([raw("first")], "second", 2)));
    if (++nextPageAttempts === 1) throw new TypeError("Transient network failure");
    return new Response(JSON.stringify(page([raw("last")], "", 2)));
  };
  try {
    const result = await client.executeCrowdStrike(connection, input);
    assert.deepEqual(result.rows, [[2]]);
    assert.equal(calls.length, 4);
    assert.equal(calls[2].toString(), calls[3].toString());
    assert.equal(nextPageAttempts, 2);
  } finally { globalThis.fetch = original; }
});

test("CVE device table deduplicates devices and sorts severity before prevalence", () => {
  const items = [raw("a"), raw("b"), raw("c", { aid: "host-2" }), raw("d", { cid: "tenant-b" }),
    raw("e", { cve: { id: "CVE-2026-2", severity: "CRITICAL", base_score: 9.8 } }),
    raw("f", { cve: { id: "CVE-2026-3", severity: "LOW" } }),
    raw("g", { status: "closed", cve: { id: "CVE-2026-4", severity: "CRITICAL" } }),
    raw("h", { cve: {} }), raw("i", { cve: { id: "CVE-2026-5", severity: "MEDIUM" } })];
  const result = adapter.summarizeVulnerabilities(items.map(adapter.normalizeVulnerability), cveOptions);
  assert.deepEqual(result.rows.map(row => row.slice(0,4)), [
    ["CVE-2026-2", "CRITICAL", 1, 1], ["CVE-2026-1", "HIGH", 3, 4],
    ["CVE-2026-5", "MEDIUM", 1, 1], ["CVE-2026-3", "LOW", 1, 1]]);
  assert.match(result.note, /1 findings without a CVE/);
  assert.equal(result.rows[0][4], 9.8);
  assert.equal(result.rows[0][5], null);
  assert.throws(() => adapter.summarizeVulnerabilities([adapter.normalizeVulnerability(raw("missing", { aid: "" }))], cveOptions), /host ID/);
  assert.equal(contract.parseQueryInput({ ...input, crowdstrike: cveOptions }).crowdstrike.view, "cve-devices");
  assert.throws(() => contract.parseQueryInput({ ...input, crowdstrike: { ...cveOptions, measure: "findings" } }), /unique hosts/);
});

test("CVE ranking finishes the whole critical population before taking top rows", async () => {
  const rows = Array.from({ length: 10 }, (_, i) => raw(`critical-${i}`, { cve: { id: `CVE-2026-${i+1}`, severity: "CRITICAL" } }));
  const extra = raw("critical-extra", { aid: "host-2", cve: { id: "CVE-2026-10", severity: "CRITICAL" } });
  await mockHttp([auth, page(rows, "second", 11), page([extra], "", 11)], async calls => {
    const result = await client.executeCrowdStrike(connection, { ...input, crowdstrike: cveOptions });
    assert.equal(result.rows.length, 10);
    assert.equal(result.rows[0][0], "CVE-2026-10");
    assert.equal(result.rows[0][2], 2);
    assert.equal(calls.length, 3, "Lower severities cannot enter an already full critical-first top ten");
    for (const call of calls.slice(1)) {
      assert.equal(call.url.searchParams.get("filter"), "(status:['open','reopen'])+cve.severity:'CRITICAL'");
      assert.deepEqual(call.url.searchParams.getAll("facet"), ["cve"]);
    }
  });
});

test("CVE collection visits lower severities only when needed and never returns partial groups", async () => {
  const high = raw("high");
  await mockHttp([auth, page([]), page([high]), page([]), page([]), page([]), page([])], async calls => {
    const result = await client.executeCrowdStrike(connection, { ...input, crowdstrike: cveOptions });
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0][1], "HIGH");
    assert.equal(calls.length, 7);
  });
  await mockHttp([auth, page([high])], async () => {
    await assert.rejects(client.executeCrowdStrike(connection, { ...input, crowdstrike: cveOptions }), /changed severity/);
  });
  await mockHttp([auth, page([], "", 5)], async () => {
    await assert.rejects(client.executeCrowdStrike(connection, { ...input, crowdstrike: cveOptions }), /before all findings/);
  });
});

test("severity count preset preserves its view and rejects incompatible options", () => {
  const preset = { ...input, crowdstrike: { ...options, view: "severity-counts" } };
  assert.equal(contract.parseQueryInput(preset).crowdstrike.view, "severity-counts");
  for (const change of [{ measure: "cves" }, { groupBy: "severity" }, { history: true }]) {
    assert.throws(() => contract.parseQueryInput({ ...preset, crowdstrike: { ...preset.crowdstrike, ...change } }), /Severity counts/);
  }
  const definition = { ...preset, title: "Severity", display: "metrics", refreshMinutes: 1440, enabled: true };
  assert.equal(contract.parseDefinition(definition, "severity").display, "metrics");
  assert.throws(() => contract.parseDefinition({ ...definition, display: "bar", chart: { category: "severity", value: "findings" } }, "severity"), /Number cards or Table/);
});

test("severity counts use six bounded metadata requests even above the collection cap", async () => {
  const counts = [312345, 400000, 1234, 7, 0, 12];
  const filter = "status:'open',status:'reopen'";
  await mockHttp([auth, ...counts.map(total => page(total ? ["finding-id"] : [], "unused-next-page", total))], async (calls) => {
    const result = await client.executeCrowdStrike(connection, { ...input, query: filter, crowdstrike: { ...options, view: "severity-counts" } });
    assert.deepEqual(result.columns.map(column => column.name), ["critical", "high", "medium", "low", "none", "unknown"]);
    assert.deepEqual(result.rows, [counts]);
    assert.equal(result.truncated, false);
    assert.match(result.note, /not a single atomic snapshot/);
    contract.validateDisplayResult(result, { display: "metrics" });
    assert.equal(calls.length, 7);
    for (const [index, call] of calls.slice(1).entries()) {
      assert.equal(call.url.pathname, "/spotlight/queries/vulnerabilities/v1");
      assert.equal(call.url.searchParams.get("limit"), "1");
      assert.equal(call.url.searchParams.get("after"), null);
      assert.equal(call.url.searchParams.get("facet"), null);
      assert.equal(call.url.searchParams.get("filter"), `(${filter})+cve.severity:'${result.columns[index].name.toUpperCase()}'`);
    }
  });
});

test("severity counts never turn missing or invalid API totals into zero", async () => {
  for (const total of [undefined, null, -1, "12", 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await mockHttp([auth, { resources: ["id"], meta: { pagination: { total } } }], async () => {
      await assert.rejects(client.executeCrowdStrike(connection, { ...input, crowdstrike: { ...options, view: "severity-counts" } }), /valid severity total/);
    });
  }
});

test("one failed severity request rejects the whole result", async () => {
  await mockHttp([auth, page(["id"], "", 100), { status: 400, body: { errors: [{ message: "Bad filter" }] } }], async () => {
    await assert.rejects(client.executeCrowdStrike(connection, { ...input, crowdstrike: { ...options, view: "severity-counts" } }), /Bad filter/);
  });
});

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

const patchModel = (await load("lib/patch-request.ts")).namespace;
const patchCve = "CVE-2026-12345";
const remedy = (id = "patch-1") => ({ id, title: "Vendor update", action: 'Install version 2.0, then restart.\nVerify "closed".', link: "https://vendor.example/patch", reference: "KB123" });
const patchRaw = (id, props = {}) => raw(id, {
  cve: { id: patchCve, severity: "CRITICAL", base_score: 9.8, vector: "CVSS:3.1/AV:N", exprt_rating: "HIGH", exploit_status: 90, exploitability_score: 3.9, impact_score: 5.9, cisa_info: { is_cisa_kev: true }, description: "Test vulnerability" },
  suppression_info: { is_suppressed: false },
  apps: [{ vendor_normalized: "Vendor", product_name_normalized: "Product", product_name_version: "Product 1.0", remediation: { ids: ["patch-1"] }, remediation_info: { recommended_id: "patch-1" } }],
  remediation: { entities: [remedy()] }, ...props
});

test("patch input accepts only an exact CVE and cannot inject FQL", () => {
  assert.deepEqual(patchModel.parsePatchInput({ cve: "cve-2026-12345", query: "status:'closed'" }), { source: "crowdstrike", cve: patchCve });
  for (const cve of ["CVE-2026-1", " CVE-2026-12345", "CVE-2026-12345'+status:'closed'", null]) assert.throws(() => patchModel.parsePatchInput({ cve }), /valid CVE/);
});

test("patch export collects beyond top 100, deduplicates findings and tenant-scopes devices", async () => {
  const rows = Array.from({ length: 103 }, (_, i) => patchRaw(`finding-${i}`, { aid: `host-${i}`, host_info: { hostname: `device-${i}` } }));
  rows.push(patchRaw("finding-0", { cid: "tenant-b", aid: "host-0", host_info: { hostname: "other-tenant-device" } }));
  await mockHttp([auth, page(rows.slice(0, 80), "next", 104), page([rows[0], ...rows.slice(80)], "", 104)], async calls => {
    const packet = await client.executePatchRequest(connection, { cve: patchCve, top: 10, query: "status:'closed'" });
    assert.equal(packet.hostCount, 104); assert.equal(packet.findingCount, 104); assert.equal(packet.csvRows, 104);
    assert.match(packet.csv, /device-102/); assert.match(packet.csv, /other-tenant-device/);
    assert.doesNotMatch(packet.body, /device-102|other-tenant-device|Host ID:|ALL AFFECTED HOSTS/);
    assert.match(packet.body, /See the attached CVE-2026-12345-patch-request.csv/);
    assert.match(packet.body, /Affected hosts: 104/);
    assert.match(packet.body, /9\.8/); assert.match(packet.body, /GMI policy, not a CrowdStrike score/);
    assert.match(packet.csv, /CVSS:3.1\/AV:N/); assert.match(packet.csv, /Install version 2.0, then restart./);
    assert.deepEqual(packet.warnings, []);
    for (const call of calls.slice(1)) {
      assert.equal(call.url.searchParams.get("filter"), `cve.id:'${patchCve}'+status:['open','reopen']`);
      assert.deepEqual(call.url.searchParams.getAll("facet"), ["cve", "host_info", "remediation"]);
    }
  });
});

test("patch export resolves only recommended IDs and keeps all application recommendations in the ticket", async () => {
  const row = patchRaw("a", { apps: [
    { product_name_normalized: "Alpha", remediation: { ids: ["patch-1"] }, remediation_info: { recommended_id: "patch-2", minimum_id: "patch-1" } },
    { product_name_normalized: "Beta", remediation: { ids: ["patch-3"] }, remediation_info: { recommended_id: "patch-3" } }
  ], remediation: { entities: [remedy()] } });
  await mockHttp([auth, page([row]), { resources: [remedy("patch-2"), remedy("patch-3")] }], async calls => {
    const packet = await client.executePatchRequest(connection, { cve: patchCve });
    assert.equal(packet.csvRows, 2); assert.equal(packet.hostCount, 1);
    const last = calls.at(-1).url;
    assert.equal(last.pathname, "/spotlight/entities/remediations/v2");
    assert.deepEqual(last.searchParams.getAll("ids"), ["patch-2", "patch-3"]);
    assert.doesNotMatch(packet.csv, /patch-1|minimum_remediation_id/);
    assert.doesNotMatch(packet.body, /patch-1/);
    assert.match(packet.body, /patch-2/);
    assert.match(packet.body, /patch-3/);
    assert.match(packet.csv, /"Alpha","","patch-2"/);
    assert.match(packet.csv, /"Beta","","patch-3"/);
    assert.doesNotMatch(packet.csv, /"Beta","","patch-1"/);
  });
});

test("patch export fails closed on incomplete, changing, or nonadvancing pages", async () => {
  for (const [replies, message] of [
    [[page([patchRaw("a")], "", 2)], /without all matching/],
    [[page([patchRaw("a")], "next", 2), page([patchRaw("b")], "", 3)], /population changed/],
    [[page([patchRaw("a")], "next", 3), page([patchRaw("a")], "next", 3)], /did not advance/],
    [[page([patchRaw("a")], "next", 2), page([patchRaw("a", { aid: "changed" })], "", 2)], /finding changed/],
    [[page([patchRaw("a", { aid: "" })])], /host ID/],
    [[page([patchRaw("a", { status: "closed" })])], /outside/],
    [[page([], "", 250001)], /250,000/],
    [[page([])], /no open/],
  ]) await mockHttp([auth, ...replies], () => assert.rejects(() => client.executePatchRequest(connection, { cve: patchCve }), message));
});

test("patch export refuses incomplete remediation responses and API failures", async () => {
  const row = patchRaw("a", { remediation: { entities: [] } });
  await mockHttp([auth, page([row]), { resources: [] }], () => assert.rejects(() => client.executePatchRequest(connection, { cve: patchCve }), /all referenced remediations/));
  await mockHttp([auth, page([row]), { status: 403, body: { errors: [{ message: "Forbidden" }] } }], () => assert.rejects(() => client.executePatchRequest(connection, { cve: patchCve }), /rejected access/));
});

test("patch output escapes CSV formulas and reports suppressed and missing details", () => {
  const row = patchModel.normalizePatchFinding(patchRaw("a", { host_info: { hostname: "=HYPERLINK(\"bad\")" }, suppression_info: { is_suppressed: true }, apps: [{ product_name_normalized: "Unmapped application" }], cve: { id: patchCve } }), patchCve);
  const packet = patchModel.buildPatchRequest(patchCve, [row], "us-1", "start", "end");
  assert.match(packet.csv, /'\=HYPERLINK/);
  assert.match(packet.body, /CVSS base score\(s\): Not supplied/);
  assert.match(packet.body, /CISA KEV: Not supplied/);
  assert.ok(packet.warnings.some(w => /Suppressed/.test(w)));
  assert.ok(packet.warnings.some(w => /actionable recommended remediation/.test(w)));
  assert.match(packet.csv, /No recommended remediation supplied/);
  assert.doesNotMatch(packet.csv, /"Unmapped application","","patch-1"/);
});


test("recommendations exclude minimum-only alternatives, preserve missing hosts, and respect app mapping", () => {
  const rows = [patchRaw("first", { apps: [
    { product_name_normalized: "Explicit", remediation_info: { recommended_id: "rec-a", minimum_id: "min-a" } },
    { product_name_normalized: "Tagged", remediation: { ids: ["rec-b", "min-a"] } },
    { product_name_normalized: "No recommendation", remediation: { ids: ["min-a"] } }
  ], remediation: { entities: [
    { ...remedy("rec-a"), recommendation_type: "minimum" },
    { ...remedy("rec-b"), recommendation_type: "recommended" },
    { ...remedy("min-a"), recommendation_type: "minimum" },
    { ...remedy("unrelated-rec"), recommendation_type: "recommended" }
  ] } }), patchRaw("second", { aid: "host-without-recommendation", apps: [], remediation: { entities: [{ ...remedy("min-only"), recommendation_type: "minimum" }] } })];
  const packet = patchModel.buildPatchRequest(patchCve, rows.map(r => patchModel.normalizePatchFinding(r, patchCve)), "us-1", "start", "end");
  assert.equal(packet.hostCount, 2); assert.equal(packet.findingCount, 2); assert.equal(packet.csvRows, 4);
  assert.match(packet.csv, /"Explicit","","rec-a"/); assert.match(packet.csv, /"Tagged","","rec-b"/);
  assert.doesNotMatch(packet.csv, /min-a|min-only|unrelated-rec|minimum_remediation_id/);
  assert.doesNotMatch(packet.body, /min-a|min-only|unrelated-rec/);
  assert.match(packet.body, /rec-a/); assert.match(packet.body, /rec-b/);
  assert.match(packet.csv, /host-without-recommendation/);
  assert.doesNotMatch(packet.body, /host-without-recommendation/);
  assert.match(packet.csv, /No recommended remediation supplied/);
  assert.equal(packet.warnings.length, 1);
});

test("finding-level recommendations work without applications and same recommended/minimum ID emits once", () => {
  const rows = [patchRaw("a", { apps: [], remediation: { entities: [{ ...remedy("rec-a"), recommendation_type: "recommended" }, { ...remedy("min-a"), recommendation_type: "minimum" }] } }),
    patchRaw("b", { apps: [{ remediation_info: { recommended_id: "patch-1", minimum_id: "patch-1" } }] })];
  const packet = patchModel.buildPatchRequest(patchCve, rows.map(r => patchModel.normalizePatchFinding(r, patchCve)), "us-1", "start", "end");
  assert.equal(packet.csvRows, 2); assert.equal(packet.hostCount, 1);
  assert.match(packet.csv, /Recommended finding-level remediation/); assert.doesNotMatch(packet.csv, /min-a/);
});
