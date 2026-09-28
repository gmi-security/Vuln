// node --experimental-vm-modules tests/spotlight-record-store.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/spotlight-record-store.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(async name => {
  const values = await import(name);
  return new SyntheticModule(Object.keys(values), function () {
    for (const key of Object.keys(values)) this.setExport(key, values[key]);
  });
});
await module.evaluate();
const { createSpotlightRecordStore } = module.namespace;

const row = (id, raw = { id }) => ({
  sourceId: id, tenantKey: "CO-147284", companyId: "CO-147284",
  hostname: "atlas-host", localIp: "10.0.0.1", externalIp: "", cve: "CVE-2026-1234",
  severity: "High", status: "open", description: "Issue", remediation: "Apply patch",
  observedAt: "2026-09-28T00:00:00.000Z", raw,
});

test("record batch preserves two CrowdStrike IDs on the same host and CVE with full payloads", async () => {
  const calls = [];
  const db = { query: async (sql, values) => {
    calls.push({ sql, values });
    return { rowCount: 2, rows: [] };
  } };
  const store = createSpotlightRecordStore(db);
  const stored = await store.writeSpotlightBatch("run-1", "CO-147284", [
    row("source-1", { id: "source-1", host_info: { local_ip: "10.0.0.1" } }),
    row("source-2", { id: "source-2", host_info: { local_ip: "10.0.0.1" } }),
  ]);
  assert.equal(stored, 2);
  const input = JSON.parse(calls.at(-1).values.find(value => typeof value === "string" && value.startsWith("[")));
  assert.deepEqual(input.map(item => item.source_id), ["source-1", "source-2"]);
  assert.equal(input[0].raw.host_info.local_ip, "10.0.0.1");
});

test("record batch rejects a missing source ID before writing", async () => {
  let queries = 0;
  const store = createSpotlightRecordStore({ query: async () => { queries++; return { rowCount: 0, rows: [] }; } });
  await assert.rejects(() => store.writeSpotlightBatch("run-1", "CO-147284", [row("")]), /source.*id/i);
  assert.equal(queries, 0);
});

test("promotion updates the completed run and active pointer in one transaction", async () => {
  const calls = [];
  const client = {
    query: async (sql) => { calls.push(String(sql).trim().split(/\s+/).slice(0, 3).join(" ")); return { rowCount: 1, rows: [{ id: "run-1" }] }; },
    release: () => { calls.push("RELEASE"); },
  };
  const store = createSpotlightRecordStore({ connect: async () => client, query: async () => ({ rows: [] }) });
  await store.completeSpotlightRun("run-1", "CO-147284");
  assert.equal(calls[0], "BEGIN");
  assert.ok(calls[1].startsWith("UPDATE spotlight_import_runs"));
  assert.ok(calls[2].startsWith("INSERT INTO spotlight_import_current"));
  assert.equal(calls[3], "COMMIT");
  assert.equal(calls[4], "RELEASE");
});
