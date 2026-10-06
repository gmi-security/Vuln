import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const expected = [
  ["crowdstrike", "CrowdStrike Connector", "CrowdStrike", "/api/crowdstrike/health"],
  ["nessus", "Nessus Connector", "Nessus", "/api/nessus/health"],
  ["spiderfoot", "SpiderFoot Connector", "SpiderFoot", "/api/spiderfoot/health"],
  ["zap", "ZAP Connector", "ZAP", "/api/zap/health"],
  ["artemis", "Artemis Connector", "Artemis", "/api/artemis/health"],
  ["nmap", "Nmap Connector", "Nmap", "/api/nmap/health"],
  ["burp", "Burp Connector", "Burp", "/api/burp/health"],
  ["n8n", "n8n Connector", "n8n", "/api/n8n/health"],
  ["vulners-bridge", "Vulners Bridge Connector", "Vulners Bridge", "/api/vulners-bridge-health"],
];

test("discovery returns the exact public connector manifest without probing health", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("discovery must not probe connectors"); };
  try {
    const { GET } = await import("../app/.well-known/sonar-health/route.ts");
    const response = await GET();
    assert.equal(response.status, 200);
    const manifest = await response.json();
    assert.deepEqual(Object.keys(manifest).sort(), ["service", "targets"]);
    assert.equal(manifest.service, "Vuln");
    assert.ok(Array.isArray(manifest.targets));
    assert.equal(manifest.targets.length, expected.length);
    assert.equal(new Set(manifest.targets.map((target) => target.id)).size, expected.length);

    for (const [index, target] of manifest.targets.entries()) {
      const [id, name, provider, healthPath] = expected[index];
      assert.deepEqual(target, { id, name, provider, checkType: "VULN_CONNECTOR", healthPath, authProfile: "NONE" });
      assert.ok(healthPath.startsWith("/") && !healthPath.startsWith("//"));
      assert.ok(existsSync(fileURLToPath(new URL(`../app${healthPath}/route.ts`, import.meta.url))));
    }
    assert.doesNotMatch(JSON.stringify(manifest), /https?:\/\/|api[_-]?key|token|password|secret|authorization|credential/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("discovery bypasses the session proxy", () => {
  const proxy = readFileSync(new URL("../proxy.ts", import.meta.url), "utf8");
  assert.ok(proxy.includes('pathname === "/.well-known/sonar-health"'));
});
