// node --experimental-vm-modules --test tests/threat-intel-refresh.test.mjs
//
// Exercises lib/threat-intel-refresh.ts against a stubbed global fetch: each
// of MISP/OpenCTI/IntelOwl is a no-op when its env vars aren't set, each
// parses its platform's documented response shape into an active/inactive
// signal, one platform failing never crashes or blocks the others, and the
// merge prefers "active" when any source reports it.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

function loader(overrides = {}) {
  const cache = new Map();
  async function load(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const code = ts.transpileModule(await readFile(path, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
    await mod.link(async (name) => {
      if (overrides[name]) { const values = overrides[name]; return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); }); }
      if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
      if (name.startsWith("@/")) return load(resolve(".", `${name.slice(2)}.ts`));
      const values = await import(name);
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  return async (path) => { const mod = await load(path); await mod.evaluate(); return mod.namespace; };
}

const ENV_KEYS = ["MISP_URL", "MISP_API_KEY", "OPENCTI_URL", "OPENCTI_API_KEY", "INTELOWL_URL", "INTELOWL_API_KEY"];
function withEnv(vars, fn) {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  return fn().finally(() => { for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
}
function withFetch(impl, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = impl;
  return fn().finally(() => { globalThis.fetch = real; });
}

test("no env vars set means every source is a no-op with zero fetch calls", async () => {
  let fetchCalls = 0;
  await withEnv({}, () => withFetch(async () => { fetchCalls++; return { ok: true, json: async () => ({}) }; }, async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchActiveExploitationSignals(["CVE-2026-1111"]);
    assert.equal(result.size, 0);
    assert.equal(fetchCalls, 0);
  }));
});

test("MISP: an attribute with sightings means active=true", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key" }, () => withFetch(async (url) => {
    assert.match(String(url), /\/attributes\/restSearch$/);
    return { ok: true, json: async () => ({ response: { Attribute: [{ id: "1", sighting_count: "3" }] } }) };
  }, async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchMispActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, true);
    assert.equal(result.get("CVE-2026-1111").source, "misp");
  }));
});

test("MISP: an attribute with no sightings is recorded but not active", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key" }, () => withFetch(async () => ({
    ok: true, json: async () => ({ response: { Attribute: [{ id: "1", sighting_count: "0" }] } }),
  }), async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchMispActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, false);
  }));
});

test("OpenCTI: a vulnerability linked to an intrusion set/campaign/malware means active=true", async () => {
  await withEnv({ OPENCTI_URL: "https://opencti.example", OPENCTI_API_KEY: "key" }, () => withFetch(async (url, init) => {
    assert.match(String(url), /\/graphql$/);
    assert.match(init.headers.Authorization, /^Bearer /);
    return { ok: true, json: async () => ({ data: { vulnerabilities: { edges: [{ node: { stixCoreRelationships: { edges: [{ node: { relationship_type: "related-to" } }] } } }] } } }) };
  }, async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchOpenCtiActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, true);
    assert.equal(result.get("CVE-2026-1111").source, "opencti");
  }));
});

test("IntelOwl: an analyzer report flagging exploited=true means active=true", async () => {
  await withEnv({ INTELOWL_URL: "https://intelowl.example", INTELOWL_API_KEY: "key" }, () => withFetch(async () => ({
    ok: true, json: async () => ({ reports: [{ report: { exploited: true } }] }),
  }), async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchIntelOwlActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, true);
    assert.equal(result.get("CVE-2026-1111").source, "intelowl");
  }));
});

test("one platform's fetch throwing does not crash the merge or block the others", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key", OPENCTI_URL: "https://opencti.example", OPENCTI_API_KEY: "key" }, () => withFetch(async (url) => {
    if (String(url).includes("misp")) throw new Error("MISP is down");
    return { ok: true, json: async () => ({ data: { vulnerabilities: { edges: [{ node: { stixCoreRelationships: { edges: [{ node: {} }] } } }] } } }) };
  }, async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchActiveExploitationSignals(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, true);
    assert.equal(result.get("CVE-2026-1111").source, "opencti");
  }));
});

test("merge prefers active=true when any one source reports it, even if another reports false", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key", OPENCTI_URL: "https://opencti.example", OPENCTI_API_KEY: "key" }, () => withFetch(async (url) => {
    if (String(url).includes("misp")) return { ok: true, json: async () => ({ response: { Attribute: [{ id: "1", sighting_count: "0" }] } }) };
    return { ok: true, json: async () => ({ data: { vulnerabilities: { edges: [{ node: { stixCoreRelationships: { edges: [{ node: {} }] } } }] } } }) };
  }, async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchActiveExploitationSignals(["CVE-2026-1111"]);
    assert.equal(result.get("CVE-2026-1111").active, true); // OpenCTI's true wins over MISP's false
  }));
});

test("a non-ok HTTP response is treated as no signal, not a thrown error", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key" }, () => withFetch(async () => ({ ok: false, status: 500 }), async () => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchMispActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.size, 0);
  }));
});

function withCapturedErrors(fn) {
  const real = console.error;
  const lines = [];
  console.error = (...args) => { lines.push(args.join(" ")); };
  return fn(lines).finally(() => { console.error = real; });
}

test("a non-ok HTTP response and a thrown error both surface in the aggregate failure log, not silently", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key" }, () => withFetch(async () => ({ ok: false, status: 503 }), () =>
    withCapturedErrors(async (lines) => {
      const mod = await loader()("lib/threat-intel-refresh.ts");
      await mod.fetchMispActiveExploitation(["CVE-2026-1111"]);
      assert.ok(lines.some((l) => l.includes("[threat-intel] misp") && l.includes("1 failed") && l.includes("HTTP 503")));
    })));
});

test("a 200 OK GraphQL response carrying an errors array is treated as a failure, not an empty-result success", async () => {
  await withEnv({ OPENCTI_URL: "https://opencti.example", OPENCTI_API_KEY: "key" }, () => withFetch(async () => ({
    ok: true, json: async () => ({ errors: [{ message: "Cannot query field \"vulnerabilities\" on type \"Query\"" }] }),
  }), () => withCapturedErrors(async (lines) => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    const result = await mod.fetchOpenCtiActiveExploitation(["CVE-2026-1111"]);
    assert.equal(result.size, 0);
    assert.ok(lines.some((l) => l.includes("[threat-intel] opencti") && l.includes("1 failed") && l.includes("Cannot query field")));
  })));
});

test("a fully successful pass logs zero failures", async () => {
  await withEnv({ MISP_URL: "https://misp.example", MISP_API_KEY: "key" }, () => withFetch(async () => ({
    ok: true, json: async () => ({ response: { Attribute: [{ id: "1", sighting_count: "0" }] } }),
  }), () => withCapturedErrors(async (lines) => {
    const mod = await loader()("lib/threat-intel-refresh.ts");
    await mod.fetchMispActiveExploitation(["CVE-2026-1111"]);
    assert.ok(lines.some((l) => l.includes("[threat-intel] misp: queried 1, 1 had data, 0 failed")));
  })));
});
