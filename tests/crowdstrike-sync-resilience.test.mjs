// node --experimental-vm-modules --test tests/crowdstrike-sync-resilience.test.mjs
//
// Removing the silent 80,000-finding cap on Spotlight sync means a large
// tenant can now legitimately fan out hundreds of hydration requests, which
// makes hitting CrowdStrike's rate limiter an expected event, not a rare
// one. These exercise the two things that keep that safe: retrying a
// throttled/5xx request instead of failing the whole sync over one blip, and
// bounding how many requests are in flight at once.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/crowdstrike.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(async (name) => {
  const values = await import(name);
  return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
});
await module.evaluate();
const { falconListAssets } = module.namespace;

async function withFetch(handler, work) {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (url, init) => { calls.push({ url: String(url), init }); return handler(String(url), init, calls.length); };
  try { return await work(calls); } finally { globalThis.fetch = original; }
}

test("a throttled request is retried instead of failing the whole sync", async () => {
  await withFetch(
    (url) => {
      if (url.includes("/oauth2/token")) return new Response(JSON.stringify({ access_token: "tok" }), { status: 200 });
      if (url.includes("/devices/queries/devices/v1")) return new Response(JSON.stringify({ resources: ["d1"], meta: { pagination: { total: 1 } } }), { status: 200 });
      return new Response("rate limited", { status: 429, headers: { "Retry-After": "0" } });
    },
    async (calls) => {
      // hydrateIds will get one 429 then... we only ever answer 429 for the
      // entities call, so this proves the retry loop runs, capped at 4
      // retries, and ultimately still surfaces a real, persistent failure —
      // it must not spin forever nor swallow a genuine outage.
      await assert.rejects(() => falconListAssets({ clientId: "a", clientSecret: "b", baseUrl: "https://x" }), /Falcon devices entities 429/);
      const entityCalls = calls.filter((c) => c.url.includes("/devices/entities/devices/v2"));
      assert.equal(entityCalls.length, 5, "one initial attempt plus 4 retries before giving up");
    },
  );
}, { timeout: 30_000 });

test("hydration never exceeds the concurrency cap even with hundreds of batches", async () => {
  let inFlight = 0, maxInFlight = 0;
  await withFetch(
    async (url) => {
      if (url.includes("/oauth2/token")) return new Response(JSON.stringify({ access_token: "tok" }), { status: 200 });
      if (url.includes("/devices/queries/devices/v1")) {
        const offset = Number(new URL(url).searchParams.get("offset"));
        const total = 500 * 40; // 40 pages of 500 ids -> 40 hydration batches
        const ids = offset < total ? Array.from({ length: 500 }, (_, i) => `id-${offset + i}`) : [];
        return new Response(JSON.stringify({ resources: ids, meta: { pagination: { total } } }), { status: 200 });
      }
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight--;
      return new Response(JSON.stringify({ resources: [] }), { status: 200 });
    },
    async () => {
      await falconListAssets({ clientId: "a", clientSecret: "b", baseUrl: "https://x" });
      assert.ok(maxInFlight <= 8, `expected at most 8 concurrent hydration requests, saw ${maxInFlight}`);
      assert.ok(maxInFlight > 1, "expected some real concurrency, not a fully sequential fallback");
    },
  );
}, { timeout: 20_000 });
