import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/dashboard-browser-client.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(() => { throw new Error("Unexpected dependency"); });
await module.evaluate();
const { readDashboardResponse, dashboardRequest } = module.namespace;
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
const html = (status = 502) => new Response("<!DOCTYPE html><html>private proxy details</html>", { status, headers: { "Content-Type": "text/html" } });

test("HTML and malformed responses yield readable status messages without leaking the page", async () => {
  for (const response of [html(), html(200), html(504), new Response("<!DOCTYPE html>", { headers: { "Content-Type": "application/json" } }), json(null), json([])]) {
    await assert.rejects(() => readDashboardResponse(response), (error) => {
      assert.match(error.message, /HTTP (200|502|504)/);
      assert.doesNotMatch(error.message, /Unexpected token|DOCTYPE|private proxy|JSON/);
      return true;
    });
  }
});

test("session failures and login redirects explain how to recover", async () => {
  await assert.rejects(() => readDashboardResponse(json({ error: "Unauthorized" }, 401)), /Sign in again/);
  const login = html(200);
  Object.defineProperties(login, { url: { value: "https://app.example/login?callbackUrl=test" }, redirected: { value: true } });
  await assert.rejects(() => readDashboardResponse(login), /Sign in again/);
  await assert.rejects(() => readDashboardResponse(json({ error: "Invalid request origin." }, 403)), /Invalid request origin/);
  await assert.rejects(() => readDashboardResponse(json({ error: "Unsupported FQL field." }, 400)), /Unsupported FQL field/);
  assert.deepEqual(await readDashboardResponse(json({ saved: true, query: { id: "tile" } }, 201)), { saved: true, query: { id: "tile" } });
});

async function withFetch(replies, work) {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    const next = replies.shift();
    if (next instanceof Error) throw next;
    assert.ok(next, "Unexpected retry"); return next;
  };
  try { await work(calls); } finally { globalThis.fetch = original; }
}

test("background reads retry a transient gateway failure once, then recover", async () => {
  await withFetch([html(502), json({ queries: [] })], async (calls) => {
    assert.deepEqual(await dashboardRequest(""), { queries: [] });
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init.headers.Accept, "application/json");
    assert.ok(calls[0].init.signal instanceof AbortSignal);
  });
  await withFetch([html(503), html(503)], async (calls) => {
    await assert.rejects(() => dashboardRequest("jobs/test"), /HTTP 503/);
    assert.equal(calls.length, 2);
  });
  await withFetch([json({ error: "Unauthorized" }, 401)], async (calls) => {
    await assert.rejects(() => dashboardRequest(""), /Sign in again/);
    assert.equal(calls.length, 1);
  });
});

test("save, preview and delete requests are never automatically replayed", async () => {
  for (const [path, method] of [["queries", "POST"], ["preview", "POST"], ["queries/test", "DELETE"]]) {
    for (const failure of [html(502), new TypeError("Network unavailable")]) {
      await withFetch([failure], async (calls) => {
        await assert.rejects(() => dashboardRequest(path, { method }), /HTTP 502|did not confirm/);
        assert.equal(calls.length, 1);
      });
    }
  }
});
