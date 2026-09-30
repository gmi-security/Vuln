import assert from "node:assert/strict";
import { after, test } from "node:test";
import { vulnersStatus } from "../lib/vulners.ts";

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
