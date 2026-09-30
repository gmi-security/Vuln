import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("alert health endpoint bypasses session proxy", async () => {
  const proxy = await readFile(new URL("../proxy.ts", import.meta.url), "utf8");
  assert.match(proxy, /pathname === "\\/api\\/alerts\\/health"/);
});

test("email alert health exposes safe structured classification", async () => {
  const route = await readFile(new URL("../app/api/alerts/health/route.ts", import.meta.url), "utf8");
  assert.match(route, /authError/);
  assert.match(route, /checkError/);
  assert.match(route, /Resend credentials rejected/);
  assert.doesNotMatch(route, /sending as/);
});
