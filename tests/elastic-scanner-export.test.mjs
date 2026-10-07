// node --experimental-vm-modules tests/elastic-scanner-export.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const modules = new Map();
async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const source = await readFile(path, "utf8");
  if (modules.has(path)) return modules.get(path);
  const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const module = new SourceTextModule(js, { identifier: path });
  modules.set(path, module);
  await module.link(async (specifier) => {
    if (specifier.startsWith("@/lib/")) return load(`lib/${specifier.slice(6)}.ts`);
    if (specifier.startsWith(".")) return load(resolve(dirname(path), `${specifier}.ts`));
    const values = await import(specifier);
    return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return module;
}

const module = await load("lib/elastic-scanner-export.ts");
await module.evaluate();
const { scannerFindingDoc, scannerBulkBody, isScannerExportable, scannerElasticConfig, SCANNER_FINDING_STREAM } = module.namespace;

const finding = (overrides = {}) => ({
  id: "FIND-42", scanId: "SCAN-1", companyId: "CO-1", companyName: "Acme",
  connector: "nessus", cve: "CVE-2026-1111", title: "Example finding", severity: "High",
  cvss: 7.5, cvssV2: 0, cvssV3: 7.5, vpr: 0, epss: 0, asset: "10.0.0.5", port: "443",
  category: "Network Service", description: "desc", remediation: "patch it", status: "Open",
  assignee: null, firstSeen: "2026-10-01T00:00:00.000Z", lastSeen: "2026-10-06T00:00:00.000Z",
  resolvedAt: null, exploitAvailable: false, kev: false, ransomware: false,
  assetExposure: "Internal", assetCriticality: "Normal", assetSource: "inferred",
  realRisk: 0, riskPriority: "High", ...overrides,
});

test("scannerFindingDoc maps a Finding onto the gmi.scanner.* field set, timestamped by lastSeen", () => {
  const doc = scannerFindingDoc(finding());
  assert.deepEqual(doc, {
    "@timestamp": "2026-10-06T00:00:00.000Z",
    "gmi.scanner.source": "nessus",
    "gmi.scanner.finding.id": "FIND-42",
    "gmi.scanner.company.id": "CO-1",
    "gmi.scanner.company.name": "Acme",
    "gmi.scanner.finding.severity": "High",
    "gmi.scanner.finding.cvss": 7.5,
    "gmi.scanner.finding.cve": "CVE-2026-1111",
    "gmi.scanner.finding.title": "Example finding",
    "gmi.scanner.finding.status": "Open",
    "gmi.scanner.finding.asset": "10.0.0.5",
    "gmi.scanner.finding.first_seen": "2026-10-01T00:00:00.000Z",
    "gmi.scanner.finding.resolved_at": null,
    "gmi.scanner.finding.exploit_available": false,
    "gmi.scanner.scan.id": "SCAN-1",
  });
});

test("isScannerExportable accepts only nessus and vulners, not crowdstrike/zap/other connectors", () => {
  assert.equal(isScannerExportable(finding({ connector: "nessus" })), true);
  assert.equal(isScannerExportable(finding({ connector: "vulners" })), true);
  for (const connector of ["crowdstrike", "zap", "defender", "qualys", "burp", "nmap", "spiderfoot", "artemis"]) {
    assert.equal(isScannerExportable(finding({ connector })), false, `${connector} must not be exportable`);
  }
});

test("scannerBulkBody emits one action+source NDJSON line pair per finding, indexing (not creating) by finding id", () => {
  const body = scannerBulkBody([finding({ id: "FIND-1" }), finding({ id: "FIND-2", connector: "vulners" })]);
  const lines = body.split("\n").filter(Boolean);
  assert.equal(lines.length, 4);
  assert.deepEqual(JSON.parse(lines[0]), { index: { _index: SCANNER_FINDING_STREAM, _id: "FIND-1" } });
  assert.equal(JSON.parse(lines[1])["gmi.scanner.finding.id"], "FIND-1");
  assert.deepEqual(JSON.parse(lines[2]), { index: { _index: SCANNER_FINDING_STREAM, _id: "FIND-2" } });
  assert.equal(JSON.parse(lines[3])["gmi.scanner.source"], "vulners");
  assert.ok(body.endsWith("\n"), "bulk NDJSON body must end with a trailing newline");
});

test("scannerBulkBody of an empty list is an empty string, not a stray newline", () => {
  assert.equal(scannerBulkBody([]), "");
});

test("scannerElasticConfig falls back from SCANNER_ELASTIC_* to APPSEC_ELASTIC_* and is null when neither is set", () => {
  const prior = {
    url: process.env.SCANNER_ELASTIC_URL, key: process.env.SCANNER_ELASTIC_API_KEY,
    appsecUrl: process.env.APPSEC_ELASTIC_URL, appsecKey: process.env.APPSEC_ELASTIC_API_KEY,
  };
  try {
    delete process.env.SCANNER_ELASTIC_URL; delete process.env.SCANNER_ELASTIC_API_KEY;
    delete process.env.APPSEC_ELASTIC_URL; delete process.env.APPSEC_ELASTIC_API_KEY;
    assert.equal(scannerElasticConfig(), null);

    process.env.APPSEC_ELASTIC_URL = "https://appsec.example.com";
    process.env.APPSEC_ELASTIC_API_KEY = "appsec-key";
    assert.deepEqual(scannerElasticConfig(), { endpoint: "https://appsec.example.com", apiKey: "appsec-key" });

    process.env.SCANNER_ELASTIC_URL = "https://scanner.example.com";
    process.env.SCANNER_ELASTIC_API_KEY = "scanner-key";
    assert.deepEqual(scannerElasticConfig(), { endpoint: "https://scanner.example.com", apiKey: "scanner-key" },
      "an explicit SCANNER_ELASTIC_* override must win over the APPSEC_ELASTIC_* fallback");
  } finally {
    for (const [k, v] of Object.entries({
      SCANNER_ELASTIC_URL: prior.url, SCANNER_ELASTIC_API_KEY: prior.key,
      APPSEC_ELASTIC_URL: prior.appsecUrl, APPSEC_ELASTIC_API_KEY: prior.appsecKey,
    })) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

// A fresh, non-shared module graph per call (unlike the top-level `load`
// above, which caches by path) -- indexScannerFindings caches "index already
// ensured" at module scope, so each scenario below needs its own isolated
// instance of lib/elastic-scanner-export.ts rather than reusing one already
// evaluated against a different fake elasticJsonRequest.
async function loadWithMockedElastic(elasticJsonRequest) {
  const cache = new Map();
  async function loadFresh(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const source = await readFile(path, "utf8");
    const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(js, { identifier: `${path}#mocked` });
    cache.set(path, mod);
    await mod.link(async (specifier) => {
      if (specifier === "./elastic-query-client") {
        return new SyntheticModule(["elasticJsonRequest"], function () { this.setExport("elasticJsonRequest", elasticJsonRequest); });
      }
      if (specifier.startsWith("@/lib/")) return loadFresh(`lib/${specifier.slice(6)}.ts`);
      if (specifier.startsWith(".")) return loadFresh(resolve(dirname(path), `${specifier}.ts`));
      const values = await import(specifier);
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  const mod = await loadFresh("lib/elastic-scanner-export.ts");
  await mod.evaluate();
  return mod.namespace;
}

test("indexScannerFindings PUTs the index once before bulk-indexing, tolerating an already-exists response", async () => {
  process.env.APPSEC_ELASTIC_URL = "https://appsec.example.com";
  process.env.APPSEC_ELASTIC_API_KEY = "appsec-key";
  try {
    const calls = [];
    let putAttempts = 0;
    const { indexScannerFindings } = await loadWithMockedElastic(async (_connection, path, method, _body, opts) => {
      calls.push({ path, method, ndjson: opts?.ndjson });
      if (method === "PUT") {
        putAttempts += 1;
        if (putAttempts === 1) throw new Error('Elastic rejected the query (HTTP 400). resource_already_exists_exception: index already exists');
        throw new Error("PUT must only be attempted once per process -- the result should be cached after the first (tolerated) failure.");
      }
      assert.equal(method, "POST");
      return { body: { items: [{ index: {} }] }, warning: false };
    });
    const result = await indexScannerFindings([finding({ id: "FIND-1" })]);
    assert.equal(result.indexed, 1);
    assert.equal(result.errors, 0);
    assert.deepEqual(calls.map(c => c.method), ["PUT", "POST"]);
    assert.ok(calls[1].ndjson.includes("FIND-1"));

    // A second export pass must not PUT again -- it's cached as ensured.
    await indexScannerFindings([finding({ id: "FIND-2" })]);
    assert.deepEqual(calls.map(c => c.method), ["PUT", "POST", "POST"]);
    assert.ok(calls[2].ndjson.includes("FIND-2"));
  } finally {
    delete process.env.APPSEC_ELASTIC_URL;
    delete process.env.APPSEC_ELASTIC_API_KEY;
  }
});

test("indexScannerFindings surfaces per-item bulk errors without throwing", async () => {
  process.env.APPSEC_ELASTIC_URL = "https://appsec.example.com";
  process.env.APPSEC_ELASTIC_API_KEY = "appsec-key";
  try {
    const { indexScannerFindings } = await loadWithMockedElastic(async (_connection, _path, method) => {
      if (method === "PUT") return { body: {}, warning: false };
      return { body: { items: [{ index: {} }, { index: { error: { reason: "mapper_parsing_exception" } } }] }, warning: false };
    });
    const result = await indexScannerFindings([finding({ id: "FIND-1" }), finding({ id: "FIND-2" })]);
    assert.equal(result.indexed, 1);
    assert.equal(result.errors, 1);
    assert.equal(result.firstError, "mapper_parsing_exception");
  } finally {
    delete process.env.APPSEC_ELASTIC_URL;
    delete process.env.APPSEC_ELASTIC_API_KEY;
  }
});
