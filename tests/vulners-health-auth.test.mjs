import assert from "node:assert/strict";
import { after, test } from "node:test";
// Run with node --experimental-vm-modules --test. Use the same TS module
// resolution as the application without executing its store or workers.
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";
const modules = new Map();
async function getModule(path) {
  path = resolve(path);
  assert.ok([resolve('lib/vulners.ts'), resolve('lib/scanner-target-scope.ts')].includes(path));
  if (!modules.has(path)) modules.set(path, new SourceTextModule(ts.transpileModule(await readFile(path, 'utf8'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText, { identifier: path }));
  return modules.get(path);
}
const adapter = await getModule('lib/vulners.ts');
await adapter.link(async (name, parent) => {
  if (name.startsWith('.')) return getModule(resolve(dirname(parent.identifier), name + '.ts'));
  assert.equal(name, 'node:net');
  const values = await import(name);
  return new SyntheticModule(Object.keys(values), function () { for (const [key, value] of Object.entries(values)) this.setExport(key, value); });
});
await adapter.evaluate();
const { vulnersStatus, vulnersBridgeStartScan, vulnersBridgeJobStatus } = adapter.namespace;

const originalFetch = globalThis.fetch;
const originalBridgeUrl = process.env.VULNERS_BRIDGE_URL;
const originalBridgeKey = process.env.VULNERS_BRIDGE_API_KEY;
after(() => {
  globalThis.fetch = originalFetch;
  if (originalBridgeUrl === undefined) delete process.env.VULNERS_BRIDGE_URL;
  else process.env.VULNERS_BRIDGE_URL = originalBridgeUrl;
  if (originalBridgeKey === undefined) delete process.env.VULNERS_BRIDGE_API_KEY;
  else process.env.VULNERS_BRIDGE_API_KEY = originalBridgeKey;
});

test("bridge credential rejection has a structured safe auth flag", async () => {
  process.env.VULNERS_BRIDGE_URL = "https://bridge.example.invalid";
  process.env.VULNERS_BRIDGE_API_KEY = "test-key";
  globalThis.fetch = async () => new Response("upstream secret details", { status: 401 });
  const result = await vulnersStatus();
  assert.equal(result.configured, true);
  assert.equal(result.reachable, false);
  assert.equal(result.authError, true);
  assert.equal(JSON.stringify(result).includes("upstream secret details"), false);
});

test("bridge unavailability has no auth flag", async () => {
  process.env.VULNERS_BRIDGE_URL = "https://bridge.example.invalid";
  process.env.VULNERS_BRIDGE_API_KEY = "test-key";
  globalThis.fetch = async () => new Response("unavailable", { status: 503 });
  const result = await vulnersStatus();
  assert.equal(result.reachable, false);
  assert.equal(result.authError, false);
});

test("bridge non-auth rejection is a check error rather than an outage", async () => {
  process.env.VULNERS_BRIDGE_URL = "https://bridge.example.invalid";
  process.env.VULNERS_BRIDGE_API_KEY = "test-key";
  globalThis.fetch = async () => new Response("rate limit detail", { status: 429 });
  const result = await vulnersStatus();
  assert.equal(result.reachable, false);
  assert.equal(result.authError, false);
  assert.equal(result.checkError, true);
  assert.equal(JSON.stringify(result).includes("rate limit detail"), false);
});

test("bridge scan launch reads the real create-response field (task_id, not id)", async () => {
  process.env.VULNERS_BRIDGE_URL = "https://bridge.example.invalid";
  process.env.VULNERS_BRIDGE_API_KEY = "test-key";
  let call = 0;
  globalThis.fetch = async (url) => {
    call += 1;
    if (call === 1) {
      assert.equal(String(url).endsWith("/api/v1/scans"), true);
      // Real gmi-vuln-api create response -- no "id" field at all.
      return new Response(
        JSON.stringify({ task_id: "e397e8e9-848a-40c4-a5a0-6cafbbc54a18", status: "created" }),
        { status: 200 },
      );
    }
    assert.equal(String(url).includes("e397e8e9-848a-40c4-a5a0-6cafbbc54a18/start"), true);
    return new Response(JSON.stringify({ task_id: "e397e8e9-848a-40c4-a5a0-6cafbbc54a18", status: "requested" }), {
      status: 200,
    });
  };
  const job = await vulnersBridgeStartScan("165.245.151.124", "regression test");
  assert.equal(job.jobId, "e397e8e9-848a-40c4-a5a0-6cafbbc54a18");
  assert.equal(job.status, "queued");
});

test("bridge job status recognizes the real \"Queued\" value as queued, not failed", async () => {
  process.env.VULNERS_BRIDGE_URL = "https://bridge.example.invalid";
  process.env.VULNERS_BRIDGE_API_KEY = "test-key";
  // Real GET /api/v1/scans/{id} response before the scanner picks up the
  // task -- confirmed live, not assumed from generic GVM status docs.
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ id: "e397e8e9-848a-40c4-a5a0-6cafbbc54a18", status: "Queued", progress: "0" }), {
      status: 200,
    });
  const result = await vulnersBridgeJobStatus("e397e8e9-848a-40c4-a5a0-6cafbbc54a18");
  assert.equal(result.status, "queued");
  assert.equal(result.error, null);
});
