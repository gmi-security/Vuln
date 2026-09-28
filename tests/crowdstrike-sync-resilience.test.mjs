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
const { falconListAssets, spotlightListFindings } = module.namespace;

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

const atlas = { clientId: "a", clientSecret: "b", baseUrl: "https://x", customerName: "Atlas Healthcare", label: "Atlas Healthcare" };
const json = (body) => new Response(JSON.stringify(body), { status: 200 });

test("Atlas Spotlight collects past the current 5,000-page guard instead of returning a partial scan", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1")) {
      const page = Number(new URL(url).searchParams.get("after") || 0);
      return json({ resources: [`id-${page}`], meta: { pagination: { after: page < 5000 ? String(page + 1) : "" } } });
    }
    const ids = new URL(url).searchParams.getAll("ids");
    return json({ resources: ids.map(id => ({ id, cve: { id: "CVE-2026-1234" }, host_info: { hostname: id } })) });
  }, async () => {
    const result = await spotlightListFindings(atlas);
    assert.equal(result.findings.length, 5001);
    assert.equal(result.findings.at(-1).hostname, "id-5000");
    assert.equal(result.truncated, false);
  });
});

test("Spotlight rejects a repeated continuation cursor rather than completing a partial scan", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["id-1"], meta: { pagination: { after: "same" } } });
    return json({ resources: [{ id: "id-1", cve: { id: "CVE-2026-1234" }, host_info: { hostname: "host-1" } }] });
  }, async () => {
    await assert.rejects(() => spotlightListFindings(atlas), /cursor.*repeat/i);
  });
});

test("Spotlight rejects an empty page that still offers a continuation cursor", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    return json({ resources: [], meta: { pagination: { after: "next" } } });
  }, async () => {
    await assert.rejects(() => spotlightListFindings(atlas), /empty.*cursor/i);
  });
});

test("Spotlight rejects incomplete entity hydration instead of reporting a smaller complete count", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["id-1", "id-2"], meta: { pagination: { after: "" } } });
    return json({ resources: [{ id: "id-1", cve: { id: "CVE-2026-1234" }, host_info: { hostname: "host-1" } }] });
  }, async () => {
    await assert.rejects(() => spotlightListFindings(atlas), /hydrat.*incomplete/i);
  });
});

test("Spotlight rejects a missing continuation cursor when the API total says more findings exist", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["id-1"], meta: { pagination: { after: "", total: 2 } } });
    return json({ resources: [{ id: "id-1", cve: { id: "CVE-2026-1234" }, host_info: { hostname: "host-1" } }] });
  }, async () => {
    await assert.rejects(() => spotlightListFindings(atlas), /pagination incomplete/i);
  });
});
