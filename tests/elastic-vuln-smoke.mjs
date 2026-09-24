// Tests the production build over loopback with disposable local session keys.
// No production credentials are read or copied into these processes.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { encode } from "next-auth/jwt";

async function run(mode) {
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  const secret = randomBytes(32).toString("hex");
  const ingestToken = randomBytes(32).toString("hex");
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
  Object.assign(env, { NODE_ENV: "production", NEXTAUTH_URL: base, NEXTAUTH_SECRET: secret,
    VULN_DISABLE_SCHEDULER: "true", ELASTIC_VULN_ENABLED: mode === "disabled" ? "false" : "true",
    ELASTIC_VULN_SAMPLE_DATA: mode === "sample" ? "true" : "false", ELASTIC_VULN_INGEST_TOKEN: ingestToken });
  // Production release must work with the existing environment unchanged.
  if (mode === "empty") delete env.ELASTIC_VULN_ENABLED;
  if (mode === "empty" && process.env.ELASTIC_TEST_DATABASE_URL) {
    const testDb = new URL(process.env.ELASTIC_TEST_DATABASE_URL);
    assert.ok(["127.0.0.1", "localhost"].includes(testDb.hostname) && testDb.pathname === "/elastic_test");
    env.ELASTIC_VULN_DATABASE_URL = testDb.toString();
  }
  const child = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-H", "127.0.0.1", "-p", String(port)],
    { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (data) => { output += data; });
  child.stderr.on("data", (data) => { output += data; });
  try {
    let started = false;
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(`${base}/login`)).ok) { started = true; break; } } catch {}
      await delay(100);
    }
    assert.ok(started, `Server did not start: ${output}`);
    const token = await encode({ secret, token: { name: "Local test", orgMember: true }, maxAge: 60 });
    const headers = { cookie: `next-auth.session-token=${token}` };
    assert.equal((await fetch(`${base}/api/elastic-vulnerabilities`)).status, 401);
    assert.equal((await fetch(`${base}/api/elastic-vulnerabilities/status`)).status, 401);
    assert.deepEqual(await (await fetch(`${base}/api/elastic-vulnerabilities/status`, { headers })).json(),
      { enabled: mode !== "disabled" });
    assert.equal((await fetch(`${base}/elastic-vulnerabilities`, { redirect: "manual" })).status, 307);
    assert.equal((await fetch(`${base}/dashboard`, { headers })).status, 200);
    assert.equal((await fetch(`${base}/api/connectors`, { headers })).status, 200);
    const result = await fetch(`${base}/api/elastic-vulnerabilities`, { headers });
    const page = await fetch(`${base}/elastic-vulnerabilities`, { headers });
    if (mode === "disabled") {
      assert.equal(result.status, 404);
      assert.equal(page.status, 404);
    } else {
      assert.equal(result.status, 200);
      assert.match(result.headers.get("cache-control"), /no-store/);
      assert.equal((await result.json()).mode, mode === "sample" ? "sample" : env.ELASTIC_VULN_DATABASE_URL ? "empty" : "unconfigured");
      assert.equal(page.status, 200);
      const html = await page.text();
      assert.match(html, mode === "sample" ? /Managed assets/ : /Asset coverage/);
      assert.match(html, mode === "sample" ? /figures are fictional/ : /No live results are available|Dashboard storage is not available/);
    }
    const url = `${base}/api/elastic-vulnerabilities/ingest`;
    assert.equal((await fetch(url, { method: "POST" })).status, mode === "disabled" ? 404 : 401);
    const ingestionHeaders = { Authorization: `Bearer ${ingestToken}`, "Content-Type": "application/json" };
    const valid = { queryId: "asset-coverage", collectedAt: new Date().toISOString(), results: { managed: 120, unmanaged: 30, coverage_pct: 80 } };
    const post = (body) => fetch(url, { method: "POST", headers: ingestionHeaders, body });
    if (mode === "sample") assert.equal((await post(JSON.stringify(valid))).status, 409);
    if (mode === "empty") {
      assert.equal((await post("not-json")).status, 400);
      assert.equal((await post(JSON.stringify({ ...valid, queryId: "other" }))).status, 400);
      assert.equal((await post(" ".repeat(17000))).status, 413);
      assert.equal((await post(JSON.stringify(valid))).status, env.ELASTIC_VULN_DATABASE_URL ? 200 : 503);
      assert.equal((await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${ingestToken}` }, body: "x" })).status, 415);
    }
    assert.equal((await fetch(`${base}/api/elastic-dashboard`)).status, 401);
    const dashboard = await fetch(`${base}/api/elastic-dashboard`, { headers });
    if (mode === "disabled") assert.equal(dashboard.status, 404);
    else {
      const model = await dashboard.json();
      assert.equal(model.canManage, false);
      assert.equal(model.endpoint, undefined);
      assert.equal(model.connected, false);
      const adminToken = await encode({ secret, token: { name: "Local admin", email: "admin@example.test", orgMember: true, orgRole: "ADMIN" }, maxAge: 120 });
      const adminHeaders = { cookie: `next-auth.session-token=${adminToken}`, origin: base, "Content-Type": "application/json" };
      const request = (route, body, requestHeaders = adminHeaders) => fetch(`${base}/api/elastic-dashboard/${route}`, { method: "POST", headers: requestHeaders, body: JSON.stringify(body) });
      for (const route of ["connection", "queries", "preview", "refresh"]) {
        assert.equal((await request(route, {}, { ...headers, origin: base, "Content-Type": "application/json" })).status, 403, `Members cannot mutate ${route}`);
        assert.equal((await request(route, {}, { ...adminHeaders, origin: "https://untrusted.example" })).status, 403);
      }
      assert.equal((await request("connection", { endpoint: "http://localhost", apiKey: "test" })).status, 400);
      assert.equal((await request("preview", { query: "" })).status, 400);
      assert.equal((await request("preview", { query: "ROW x = 1" })).status, env.ELASTIC_VULN_DATABASE_URL ? 409 : 503);
      assert.equal((await request("queries", { title: "x".repeat(34000) })).status, 413);
      const adminModel = await (await fetch(`${base}/api/elastic-dashboard`, { headers: adminHeaders })).json();
      assert.equal(adminModel.canManage, true);
      if (mode === "empty") {
        const html = await (await fetch(`${base}/elastic-vulnerabilities`, { headers: adminHeaders })).text();
        assert.match(html, /Add query/);
        assert.match(html, /Connection/);
      }
    }
    console.log(`PASS: ${mode} mode — sessions, admin roles, CSRF, page/API, existing routes, ingestion guards`);
  } finally {
    child.kill();
    await once(child, "exit");
  }
}
for (const mode of ["disabled", "sample", "empty"]) await run(mode);
