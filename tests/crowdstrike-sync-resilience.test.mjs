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
const { falconListAssets, spotlightListFindings, spotlightFindingBatches, falconProbeCounts } = module.namespace;

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

test("Spotlight query retries a transient 500 and imports the returned finding", async () => {
  let queryAttempts = 0;
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1")) {
      queryAttempts++;
      if (queryAttempts === 1) return new Response("temporary error", { status: 500 });
      return json({ resources: ["source-1"], meta: { pagination: { after: "", total: 1 } } });
    }
    if (url.includes("/spotlight/entities/vulnerabilities/v2"))
      return json({ resources: [{ id: "source-1", cve: { id: "CVE-2026-1234" }, host_info: { hostname: "atlas-host" } }] });
    throw new Error(`Unexpected request: ${url}`);
  }, async () => {
    const result = await spotlightListFindings(atlas);
    assert.equal(queryAttempts, 2);
    assert.deepEqual(result.findings.map(finding => finding.id), ["source-1"]);
  });
});

test("Spotlight renews an expired token on a later query page without losing earlier findings", async () => {
  let tokenRequests = 0;
  let expiredPageAttempts = 0;
  await withFetch((url, init) => {
    if (url.includes("/oauth2/token")) return json({ access_token: `token-${++tokenRequests}` });
    const request = new URL(url);
    const authorization = init.headers.Authorization;
    if (request.pathname.includes("/spotlight/queries/vulnerabilities/v1")) {
      if (!request.searchParams.has("after")) return json({ resources: ["source-1"], meta: { pagination: { after: "next", total: 2 } } });
      expiredPageAttempts++;
      if (authorization === "Bearer token-1") return new Response("expired", { status: 401 });
      assert.equal(authorization, "Bearer token-2");
      return json({ resources: ["source-2"], meta: { pagination: { after: "", total: 2 } } });
    }
    if (request.pathname.includes("/spotlight/entities/vulnerabilities/v2")) {
      assert.equal(authorization, "Bearer token-2");
      return json({ resources: request.searchParams.getAll("ids").map(id => ({
        id, cve: { id: "CVE-2026-1234" }, host_info: { hostname: "atlas-host" },
      })) });
    }
    throw new Error(`Unexpected request: ${url}`);
  }, async () => {
    const result = await spotlightListFindings(atlas);
    assert.deepEqual(result.findings.map(finding => finding.id), ["source-1", "source-2"]);
    assert.equal(tokenRequests, 2);
    assert.equal(expiredPageAttempts, 2);
  });
});

test("concurrent Spotlight hydration shares one token renewal", async () => {
  let tokenRequests = 0;
  await withFetch((url, init) => {
    if (url.includes("/oauth2/token")) return json({ access_token: `token-${++tokenRequests}` });
    const request = new URL(url);
    if (request.pathname.includes("/spotlight/queries/vulnerabilities/v1")) {
      const page = Number(request.searchParams.get("after") || 0);
      return json({ resources: [`source-${page}`], meta: { pagination: { after: page < 7 ? String(page + 1) : "", total: 8 } } });
    }
    if (request.pathname.includes("/spotlight/entities/vulnerabilities/v2")) {
      if (init.headers.Authorization === "Bearer token-1") return new Response("expired", { status: 401 });
      assert.equal(init.headers.Authorization, "Bearer token-2");
      return json({ resources: request.searchParams.getAll("ids").map(id => ({
        id, cve: { id: "CVE-2026-1234" }, host_info: { hostname: id },
      })) });
    }
    throw new Error(`Unexpected request: ${url}`);
  }, async () => {
    const result = await spotlightListFindings(atlas);
    assert.equal(result.findings.length, 8);
    assert.equal(tokenRequests, 2);
  });
});

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

test("debug count probe reads pagination totals without downloading assets or vulnerabilities", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/devices/queries/devices/v1"))
      return json({ resources: ["device-1"], meta: { pagination: { total: 1466 } } });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["vuln-1"], meta: { pagination: { total: 120345 } } });
    throw new Error(`Unexpected full-fetch request: ${url}`);
  }, async (calls) => {
    const counts = await falconProbeCounts(atlas);
    assert.equal(counts.hostsAvailable, 1466);
    assert.equal(counts.spotlightFindingsAvailable, 120345);
    assert.equal(calls.length, 3, "token plus one query for each count");
    assert.ok(calls.every(({ url }) => !url.includes("/entities/")));
  });
});

test("Spotlight streams more than 80,000 source records in bounded batches without merging a shared host and CVE", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    const request = new URL(url);
    if (request.pathname.includes("/spotlight/queries/vulnerabilities/v1")) {
      const page = Number(request.searchParams.get("after") || 0);
      const ids = Array.from({ length: 400 }, (_, index) => `source-${page * 400 + index}`);
      return json({ resources: ids, meta: { pagination: { after: page < 200 ? String(page + 1) : "", total: 80400 } } });
    }
    if (request.pathname.includes("/spotlight/entities/vulnerabilities/v2")) {
      const ids = request.searchParams.getAll("ids");
      return json({ resources: ids.map(id => ({
        id, cve: { id: "CVE-2026-1234", description: "Issue" },
        host_info: { hostname: "atlas-host", local_ip: "10.0.0.1", external_ip: "", os_version: "Windows" },
        remediation: { entities: [{ action: "Apply patch" }] }, status: "open", severity: "HIGH",
      })) });
    }
    throw new Error(`Unexpected request: ${url}`);
  }, async () => {
    let count = 0;
    let batches = 0;
    const firstIds = [];
    for await (const batch of spotlightFindingBatches(atlas)) {
      assert.ok(batch.length > 0 && batch.length <= 3200);
      if (batches === 0) {
        firstIds.push(batch[0].id, batch[1].id);
        assert.equal(batch[0].raw.id, "source-0", "the full vendor record must survive parsing for durable storage");
        assert.equal(batch[0].raw.host_info.local_ip, "10.0.0.1");
      }
      count += batch.length;
      batches++;
    }
    assert.equal(count, 80400);
    assert.deepEqual(firstIds, ["source-0", "source-1"]);
    assert.ok(batches > 1);
  });
});

test("Spotlight rejects a hydrated record without its source vulnerability ID", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["source-1"], meta: { pagination: { after: "", total: 1 } } });
    return json({ resources: [{ cve: { id: "CVE-2026-1234" }, host_info: { hostname: "atlas-host" } }] });
  }, async () => {
    await assert.rejects(async () => {
      for await (const _batch of spotlightFindingBatches(atlas)) { /* consume */ }
    }, /source.*id/i);
  });
});

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

test("Spotlight rejects entity hydration with the wrong IDs even when the count matches", async () => {
  await withFetch((url) => {
    if (url.includes("/oauth2/token")) return json({ access_token: "tok" });
    if (url.includes("/spotlight/queries/vulnerabilities/v1"))
      return json({ resources: ["id-1", "id-2"], meta: { pagination: { after: "", total: 2 } } });
    return json({ resources: ["id-1", "id-1"].map(id => ({ id, cve: { id: "CVE-2026-1234" } })) });
  }, async () => {
    await assert.rejects(() => spotlightListFindings(atlas), /hydrat.*ids.*mismatch/i);
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
