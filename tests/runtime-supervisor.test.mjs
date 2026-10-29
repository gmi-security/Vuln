import assert from "node:assert/strict";
import test from "node:test";
import { access, mkdtemp, writeFile, rm } from "node:fs/promises";
import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import http from "node:http";
import { setTimeout as delay } from "node:timers/promises";

const launcher = await import("../scripts/start-app.mjs").catch(error => {
  if (error.code === "ERR_MODULE_NOT_FOUND") return {};
  throw error;
});
const serverScript = fileURLToPath(new URL("./fixtures/runtime-child.mjs", import.meta.url));
const valid = { NODE_ENV: "production", VULN_RUNTIME_SPLIT: "true", VULN_PLATFORM_STORE: "sql" };
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const configuration = extra => ({ ...launcher.createLaunchConfiguration([], { ...process.env, ...valid, ...extra }, "linux"),
  port: 0,
  // Windows has no Unix sockets. The production launcher still refuses split
  // mode there; this private pipe exercises the same Node HTTP transport.
  socketPath: process.platform === "win32" ? `\\\\.\\pipe\\vuln-supervisor-${randomUUID()}` : undefined,
});

test("split is opt in and legacy retains the exact Next start arguments", () => {
  assert.equal(typeof launcher.createLaunchConfiguration, "function");
  const args = ["-H", "127.0.0.1", "-p", "3456", "--keepAliveTimeout", "6000"];
  const result = launcher.createLaunchConfiguration(args, {}, "linux");
  assert.equal(result.split, false);
  assert.deepEqual(result.args, args);
  assert.equal(result.env.NODE_ENV, "production");
});

test("split accepts existing host/port options while preserving operator heap settings", () => {
  assert.equal(typeof launcher.createLaunchConfiguration, "function");
  const result = launcher.createLaunchConfiguration(["-H", "127.0.0.1", "--port=4000", "--keepAliveTimeout", "8000"], { ...valid, NODE_OPTIONS: "--max-old-space-size=8192" }, "linux");
  assert.equal(result.hostname, "127.0.0.1"); assert.equal(result.port, 4000); assert.equal(result.keepAliveTimeout, 8000);
  assert.equal(result.env.NODE_OPTIONS, "--max-old-space-size=8192");
  assert.equal(launcher.createLaunchConfiguration([], { ...valid, PORT: "4567" }, "linux").port, 4567);
});

test("per-role heap overrides accept bounded integer MiB values without replacing inherited Node options", () => {
  const result = launcher.createLaunchConfiguration([], { ...valid, VULN_WEB_HEAP_MB: "8192", VULN_WORKER_HEAP_MB: "16384",
    NODE_OPTIONS: "--max-old-space-size=24576 --enable-source-maps" }, "linux");
  assert.equal(result.webHeapMb, 8192); assert.equal(result.workerHeapMb, 16384);
  assert.equal(result.env.NODE_OPTIONS, "--max-old-space-size=24576 --enable-source-maps");
  for (const name of ["VULN_WEB_HEAP_MB", "VULN_WORKER_HEAP_MB"]) {
    for (const value of ["", "127", "65537", "-512", "1.5", "Infinity", "private-not-a-number"])
      assert.throws(() => launcher.createLaunchConfiguration([], { ...valid, [name]: value }, "linux"),
        error => error.message.includes(name) && !error.message.includes(value || "private-not-a-number"));
  }
  const limits = launcher.createLaunchConfiguration([], { ...valid, VULN_WEB_HEAP_MB: "128", VULN_WORKER_HEAP_MB: "65536" }, "linux");
  assert.equal(limits.webHeapMb, 128); assert.equal(limits.workerHeapMb, 65536);
  const inherited = launcher.createLaunchConfiguration([], valid, "linux");
  assert.equal(inherited.webHeapMb, undefined); assert.equal(inherited.workerHeapMb, undefined);
});

test("real child launches keep web/writer overrides and give only the summary worker a 1 GiB heap", { timeout: 5000 }, async () => {
  const config = configuration({ VULN_WEB_HEAP_MB: "128", VULN_WORKER_HEAP_MB: "256", NODE_OPTIONS: "--max-old-space-size=1024",
    PRIVATE_TEST_VALUE: "private-heap-test-value" });
  config.auxiliaryWorkers = ["summary", "reporting"].map(role => ({ role, script: fileURLToPath(new URL("./fixtures/runtime-auxiliary.mjs", import.meta.url)), args: [] }));
  const controller = new AbortController(), args = new Map(), events = [];
  const status = await launcher.superviseRuntime(config, { serverScript, signal: controller.signal, shutdownMs: 500,
    onEvent(event, child) {
      events.push(event);
      if (event.event === "started") args.set(event.role, child.spawnargs);
      if (event.event === "ready" && event.role === "web") controller.abort();
    } });
  assert.equal(status, 0);
  assert.ok(args.get("web").includes("--max-old-space-size=128"));
  assert.ok(args.get("worker").includes("--max-old-space-size=256"));
  assert.ok(args.get("summary").includes("--max-old-space-size=1024"));
  assert.ok(args.get("reporting").includes("--max-old-space-size=512"));
  assert.equal(JSON.stringify(events).includes("private-heap-test-value"), false);
});

test("explicit split rejects unsupported storage/platform and malformed launch options", () => {
  assert.equal(typeof launcher.createLaunchConfiguration, "function");
  for (const env of [{ ...valid, NODE_ENV: "development" }, { ...valid, VULN_PLATFORM_STORE: "legacy" }])
    assert.throws(() => launcher.createLaunchConfiguration([], env, "linux"));
  assert.throws(() => launcher.createLaunchConfiguration([], valid, "win32"));
  for (const args of [["--port", "no"], ["--port", "65536"], ["--hostname"], ["--unknown"], ["--keepAliveTimeout", "-1"]])
    assert.throws(() => launcher.createLaunchConfiguration(args, valid, "linux"));
});

test("dedicated reporting workers start only when enabled and scheduler isolation suppresses both", () => {
  assert.equal(typeof launcher.createLaunchConfiguration, "function");
  assert.deepEqual(launcher.createLaunchConfiguration([], valid, "linux").auxiliaryWorkers, []);
  const enabled = { ...valid, VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED: "true", VULN_REPORTING_WORKER_ENABLED: "true" };
  const workers = launcher.createLaunchConfiguration([], enabled, "linux").auxiliaryWorkers;
  assert.deepEqual(workers.map(worker => worker.role), ["summary", "reporting"]);
  assert.ok(workers[0].args.includes("--load-env"));
  assert.deepEqual(launcher.createLaunchConfiguration([], { ...enabled, VULN_DISABLE_SCHEDULER: "true" }, "linux").auxiliaryWorkers, []);
});

test("supervisor starts one private worker before web and removes children and private directory on stop", { timeout: 10000 }, async () => {
  assert.equal(typeof launcher.superviseRuntime, "function");
  const controller = new AbortController(), events = [];
  let privateMode;
  const status = await launcher.superviseRuntime(configuration(), { serverScript, signal: controller.signal, shutdownMs: 500,
    onEvent(event) {
      events.push(event);
      if (event.event === "private-directory") privateMode = statSync(event.path).mode & 0o777;
      if (event.event === "ready" && event.role === "web") controller.abort();
    } });
  assert.equal(status, 0);
  assert.deepEqual(events.filter(event => event.event === "ready").map(event => event.role), ["worker", "web"]);
  const started = events.filter(event => event.event === "started");
  assert.equal(started.length, 2);
  if (process.platform !== "win32") assert.equal(privateMode, 0o700);
  assert.ok(started.every(event => !alive(event.pid)));
  await assert.rejects(access(events.find(event => event.event === "private-directory").path), { code: "ENOENT" });
});

test("launcher reads .env.local before choosing split mode and never logs its values", { timeout: 10000 }, async context => {
  const directory = await mkdtemp(join(tmpdir(), "vuln-launch-test-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, ".env.local"), "VULN_RUNTIME_SPLIT=true\nVULN_PLATFORM_STORE=legacy\nPRIVATE_TEST_VALUE=never-print-this-value\n");
  const env = { ...process.env, NODE_ENV: "production" };
  for (const name of ["VULN_RUNTIME_SPLIT", "VULN_PLATFORM_STORE", "__NEXT_PROCESSED_ENV"]) delete env[name];
  const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/start-app.mjs", import.meta.url))], { cwd: directory, env, windowsHide: true });
  let output = ""; child.stdout.on("data", chunk => { output += chunk; }); child.stderr.on("data", chunk => { output += chunk; });
  const code = await new Promise(resolve => child.once("exit", resolve));
  assert.equal(code, 1);
  assert.match(output, /VULN_RUNTIME_SPLIT requires Linux, production, and VULN_PLATFORM_STORE=sql/);
  assert.doesNotMatch(output, /never-print-this-value/);
});

test("auxiliary worker exit tears down its generation and the wrapper handles graceful shutdown", { timeout: 10000 }, async () => {
  assert.equal(typeof launcher.superviseRuntime, "function");
  const config = configuration(), events = [], children = [];
  config.auxiliaryWorkers = ["summary", "reporting"].map(role => ({ role,
    script: fileURLToPath(new URL("./fixtures/runtime-auxiliary.mjs", import.meta.url)), args: [] }));
  const status = await launcher.superviseRuntime(config, { serverScript, maxRestarts: 0, shutdownMs: 1000,
    onEvent(event, child) {
      events.push(event);
      if (event.event === "started") {
        children.push(child);
        if (event.role === "summary") child.once("message", message => {
          if (message?.type === "fixture-auxiliary-ready") child.send({ type: "fixture-crash" });
        });
      }
    } });
  assert.equal(status, 1);
  assert.ok(events.some(event => event.event === "exited" && event.role === "summary" && event.code === 7));
  assert.ok(events.some(event => event.event === "exited" && event.role === "reporting" && event.code === 0));
  assert.ok(children.every(child => !alive(child.pid)));
});

test("successful auxiliary exit leaves the public server and writer running without a restart", { timeout: 5000 }, async context => {
  const controller = new AbortController(), events = [];
  context.after(() => controller.abort());
  const config = configuration({ FIXTURE_AUXILIARY_EXIT_ZERO: "true" });
  config.auxiliaryWorkers = [{ role: "summary", script: fileURLToPath(new URL("./fixtures/runtime-auxiliary.mjs", import.meta.url)), args: [] }];
  let stopScheduled = false;
  const status = await launcher.superviseRuntime(config, { serverScript, maxRestarts: 0, shutdownMs: 500, signal: controller.signal,
    onEvent(event) {
      events.push(event);
      if (!stopScheduled && events.some(value => value.event === "ready" && value.role === "web") &&
          events.some(value => value.event === "exited" && value.role === "summary" && value.code === 0)) {
        stopScheduled = true;
        setTimeout(() => controller.abort(), 50);
      }
    } });
  assert.equal(status, 0);
  assert.deepEqual(events.filter(event => event.event === "started").map(event => event.role), ["worker", "summary", "web"]);
  assert.equal(events.some(event => event.event === "generation-failed"), false);
  assert.ok(events.some(event => event.event === "auxiliary-inactive" && event.role === "summary"));
});

test("worker crashes restart the entire pair with a bounded budget and no overlapping writers", { timeout: 15000 }, async () => {
  assert.equal(typeof launcher.superviseRuntime, "function");
  const events = [], children = new Map();
  const status = await launcher.superviseRuntime(configuration({ FIXTURE_CRASH_ROLE: "worker" }), {
    serverScript, maxRestarts: 2, restartDelayMs: 5, shutdownMs: 200,
    onEvent(event, child) {
      events.push(event);
      if (event.event === "started") children.set(`${event.role}-${event.attempt}`, child);
      if (event.event === "ready" && event.role === "web") children.get(`worker-${event.attempt}`).send({ type: "fixture-crash" });
    },
  });
  assert.equal(status, 1);
  const workers = events.filter(event => event.event === "started" && event.role === "worker");
  assert.equal(workers.length, 3);
  assert.equal(events.filter(event => event.event === "started" && event.role === "web").length, 3);
  for (let attempt = 1; attempt < 3; attempt++) {
    const next = events.findIndex(event => event.event === "started" && event.role === "worker" && event.attempt === attempt);
    for (const role of ["web", "worker"]) assert.ok(events.findIndex(event => event.event === "exited" && event.role === role && event.attempt === attempt - 1) < next);
  }
  assert.ok([...children.values()].every(child => !alive(child.pid)));
});

test("a web crash restarts only web and preserves the live import worker", { timeout: 10000 }, async context => {
  const controller = new AbortController(), events = [], children = new Map();
  context.after(() => controller.abort());
  let webStarts = 0, originalWorker;
  const status = await launcher.superviseRuntime(configuration({ FIXTURE_CRASH_ROLE: "web" }), {
    serverScript, signal: controller.signal, maxRestarts: 1, restartDelayMs: 5, shutdownMs: 200,
    onEvent(event, child) {
      events.push(event);
      if (event.event === "started") {
        children.set(event.pid, child);
        if (event.role === "worker") originalWorker ??= event.pid;
        if (event.role === "web") webStarts++;
      }
      if (event.event === "ready" && event.role === "web") {
        if (webStarts === 1) child.send({ type: "fixture-crash" });
        else { assert.equal(alive(originalWorker), true, "import worker must survive web replacement"); controller.abort(); }
      }
    },
  });
  assert.equal(status, 0);
  assert.equal(events.filter(event => event.event === "started" && event.role === "worker").length, 1);
  assert.equal(webStarts, 2);
  assert.ok([...children.keys()].every(pid => !alive(pid)));
});

test("aborting during worker startup never starts web and reaps the worker", { timeout: 10000 }, async () => {
  assert.equal(typeof launcher.superviseRuntime, "function");
  const controller = new AbortController(), events = [];
  const status = await launcher.superviseRuntime(configuration({ FIXTURE_PREPARE_DELAY: "5000" }), { serverScript,
    signal: controller.signal, shutdownMs: 100, onEvent(event) {
      events.push(event); if (event.event === "started") controller.abort();
    } });
  assert.equal(status, 0);
  const started = events.filter(event => event.event === "started");
  assert.deepEqual(started.map(event => event.role), ["worker"]);
  assert.ok(started.every(event => !alive(event.pid)));
});

test("a worker that never becomes ready exhausts a bounded startup budget without exposing web", { timeout: 10000 }, async () => {
  assert.equal(typeof launcher.superviseRuntime, "function");
  const events = [];
  const status = await launcher.superviseRuntime(configuration({ FIXTURE_PREPARE_DELAY: "5000" }), { serverScript,
    maxRestarts: 1, startupMs: 200, shutdownMs: 100, restartDelayMs: 1, onEvent(event) { events.push(event); } });
  assert.equal(status, 1);
  const started = events.filter(event => event.event === "started");
  assert.deepEqual(started.map(event => event.role), ["worker", "worker"]);
  assert.ok(started.every(event => !alive(event.pid)));
});

test("loss of supervisor IPC stops both HTTP and auxiliary workers instead of orphaning writers", { timeout: 10000 }, async context => {
  const directory = await mkdtemp(join(tmpdir(), "vuln-orphan-test-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  for (const auxiliary of [false, true]) {
    const args = auxiliary ? [fileURLToPath(new URL("../scripts/runtime-server.mjs", import.meta.url)),
      fileURLToPath(new URL("./fixtures/runtime-auxiliary.mjs", import.meta.url))] : [serverScript];
    const child = spawn(process.execPath, args, { env: { ...process.env,
      VULN_RUNTIME_ROLE: auxiliary ? "summary" : "worker", VULN_RUNTIME_AUXILIARY: String(auxiliary),
      VULN_RUNTIME_SOCKET: process.platform === "win32" ? `\\\\.\\pipe\\vuln-orphan-${randomUUID()}` : join(directory, "worker.sock"),
      VULN_RUNTIME_TOKEN: "supervisor-owned-test-token", VULN_RUNTIME_PORT: "0",
    }, stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true });
    context.after(() => { if (alive(child.pid)) child.kill("SIGKILL"); });
    const exited = once(child, "exit");
    await once(child, "message"); child.disconnect();
    const [code] = await exited;
    assert.equal(code, 1); assert.equal(alive(child.pid), false);
  }
});

test("HTTP worker exits within one second after owner disconnect even with a held request", { timeout: 5000 }, async context => {
  const directory = await mkdtemp(join(tmpdir(), "vuln-held-test-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const socketPath = process.platform === "win32" ? `\\\\.\\pipe\\vuln-held-${randomUUID()}` : join(directory, "worker.sock");
  const child = spawn(process.execPath, [serverScript], { env: { ...process.env, VULN_RUNTIME_ROLE: "worker",
    VULN_RUNTIME_SOCKET: socketPath, VULN_RUNTIME_TOKEN: "test-owner-token", VULN_RUNTIME_PORT: "0", FIXTURE_HOLD_REQUEST: "true",
  }, stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true });
  context.after(() => { if (alive(child.pid)) child.kill("SIGKILL"); });
  const exited = once(child, "exit"); await once(child, "message");
  const request = http.request({ socketPath, path: "/api/companies", headers: { "x-vuln-runtime-token": "test-owner-token" } });
  request.on("error", () => {}); context.after(() => request.destroy());
  request.end(); const [response] = await once(request, "response"); response.on("error", () => {});
  const before = Date.now(); child.disconnect();
  const result = await Promise.race([exited.then(([code]) => ({ code })), delay(1000).then(() => ({ timedOut: true }))]);
  assert.equal(result.timedOut, undefined); assert.equal(result.code, 1); assert.ok(Date.now() - before < 1000);
});

test("force-killing the supervisor reaps its HTTP and auxiliary children even when work cannot drain", { timeout: 6000 }, async context => {
  const child = spawn(process.execPath, [fileURLToPath(new URL("./fixtures/runtime-supervisor.mjs", import.meta.url))], {
    env: { ...process.env }, stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true,
  });
  const pids = [], events = []; let directory;
  context.after(async () => {
    for (const pid of [child.pid, ...pids]) if (alive(pid)) process.kill(pid, "SIGKILL");
    if (directory) await rm(directory, { recursive: true, force: true });
  });
  await new Promise(resolve => child.on("message", event => {
    events.push(event);
    if (event.event === "private-directory") directory = event.path;
    if (event.event === "started") pids.push(event.pid);
    if (event.event === "ready" && event.role === "web") resolve();
  }));
  assert.deepEqual(events.filter(event => event.event === "started").map(event => event.role), ["worker", "summary", "web"]);
  const exited = once(child, "exit"); child.kill("SIGKILL"); await exited;
  const deadline = Date.now() + 1000;
  while (pids.some(alive) && Date.now() < deadline) await delay(20);
  assert.ok(pids.every(pid => !alive(pid)), "all writer processes must exit when their supervisor disappears");
});
