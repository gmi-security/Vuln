import { spawn } from "node:child_process";
import { mkdtemp, chmod, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";

const require = createRequire(import.meta.url);
const runtimeScript = fileURLToPath(new URL("./runtime-server.mjs", import.meta.url));
const deferred = () => { let resolveValue; const promise = new Promise(done => { resolveValue = done; }); return { promise, resolve: resolveValue }; };

export function createLaunchConfiguration(args, sourceEnv, platform = process.platform) {
  const env = { ...sourceEnv, NODE_ENV: sourceEnv.NODE_ENV || "production" };
  if (env.VULN_RUNTIME_SPLIT !== "true") return { split: false, args: [...args], env };
  if (platform !== "linux" || env.NODE_ENV !== "production" || env.VULN_PLATFORM_STORE !== "sql")
    throw new Error("VULN_RUNTIME_SPLIT requires Linux, production, and VULN_PLATFORM_STORE=sql");
  let hostname = "0.0.0.0", port = env.PORT || "3000", keepAliveTimeout;
  for (let index = 0; index < args.length; index++) {
    const [flag, inline] = args[index].split("=", 2);
    if (!["-H", "--hostname", "-p", "--port", "--keepAliveTimeout"].includes(flag)) throw new Error(`Unsupported split runtime option: ${flag}`);
    const value = inline ?? args[++index];
    if (!value || value.startsWith("-")) throw new Error(`Missing value for ${flag}`);
    if (flag === "-H" || flag === "--hostname") hostname = value;
    else if (flag === "--keepAliveTimeout") keepAliveTimeout = value;
    else port = value;
  }
  if (!/^\d+$/.test(String(port)) || Number(port) < 1 || Number(port) > 65535) throw new Error("Invalid runtime port");
  if (keepAliveTimeout !== undefined && (!/^\d+$/.test(String(keepAliveTimeout)) || !Number.isSafeInteger(Number(keepAliveTimeout)))) throw new Error("Invalid keep-alive timeout");
  const heapSize = name => {
    if (env[name] === undefined) return undefined;
    const value = Number(env[name]);
    if (!/^\d+$/.test(String(env[name])) || !Number.isSafeInteger(value) || value < 128 || value > 65536)
      throw new Error(`${name} must be an integer from 128 through 65536 MiB`);
    return value;
  };
  const webHeapMb = heapSize("VULN_WEB_HEAP_MB"), workerHeapMb = heapSize("VULN_WORKER_HEAP_MB");
  const auxiliaryWorkers = [];
  if (env.VULN_DISABLE_SCHEDULER !== "true") {
    if (env.VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED === "true") auxiliaryWorkers.push({ role: "summary",
      script: fileURLToPath(new URL("./spotlight-summary-worker.mjs", import.meta.url)), args: ["--load-env"] });
    if (env.VULN_REPORTING_WORKER_ENABLED === "true") auxiliaryWorkers.push({ role: "reporting",
      script: fileURLToPath(new URL("./customer-reporting-worker.mjs", import.meta.url)), args: [] });
  }
  return { split: true, env, hostname, port: Number(port), keepAliveTimeout: keepAliveTimeout === undefined ? undefined : Number(keepAliveTimeout),
    webHeapMb, workerHeapMb, auxiliaryWorkers };
}

async function stopChild(record, shutdownMs) {
  if (record.finished) return;
  if (record.child.connected) record.child.send({ type: "shutdown" }, () => {});
  else record.child.kill("SIGTERM");
  const exitedWithin = async milliseconds => {
    let timer;
    try {
      return await Promise.race([record.done.then(() => true), new Promise(done => { timer = setTimeout(() => done(false), milliseconds); })]);
    } finally { clearTimeout(timer); }
  };
  if (await exitedWithin(shutdownMs)) return;
  record.child.kill("SIGKILL");
  const killed = await exitedWithin(5000);
  if (!killed) throw new Error("Could not stop runtime child; refusing to create another writer");
}

export async function superviseRuntime(configuration, {
  serverScript = runtimeScript, signal, maxRestarts = 3, restartDelayMs = 1000,
  startupMs = 120000, shutdownMs = 10000,
  onEvent = event => console.log(JSON.stringify({ runtime: "supervisor", ...event })),
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "vuln-runtime-"));
  await chmod(directory, 0o700);
  const socketPath = configuration.socketPath ?? join(directory, "worker.sock");
  const token = randomBytes(32).toString("hex");
  const stopped = deferred(), abort = () => stopped.resolve({ type: "stop" });
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  onEvent({ event: "private-directory", path: directory });
  try {
    for (let attempt = 0; attempt <= maxRestarts && !signal?.aborted; attempt++) {
      const records = [], failed = deferred();
      const start = (role, auxiliary) => {
        const env = { ...configuration.env, VULN_RUNTIME_ROLE: role, VULN_RUNTIME_SOCKET: socketPath, VULN_RUNTIME_TOKEN: token,
          VULN_RUNTIME_HOST: configuration.hostname, VULN_RUNTIME_PORT: String(configuration.port),
          ...(configuration.keepAliveTimeout === undefined ? {} : { VULN_RUNTIME_KEEP_ALIVE_MS: String(configuration.keepAliveTimeout) }),
          VULN_RUNTIME_AUXILIARY: auxiliary ? "true" : "false" };
        const heapMb = role === "web" ? configuration.webHeapMb : configuration.workerHeapMb;
        // Explicit CLI limits override only the inherited heap setting; retain
        // the rest of NODE_OPTIONS and its current behavior when no limit is set.
        const args = auxiliary ? ["--max-old-space-size=512", runtimeScript, auxiliary.script, ...auxiliary.args]
          : [...(heapMb === undefined ? [] : [`--max-old-space-size=${heapMb}`]), serverScript];
        const child = spawn(process.execPath, args, { env, stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true });
        const ready = deferred(), done = deferred();
        const record = { role, child, ready: ready.promise, done: done.promise, finished: false };
        records.push(record);
        const exit = (code, signal) => {
          if (record.finished) return;
          record.finished = true;
          const event = { event: "exited", role, pid: child.pid, attempt, code, signal };
          onEvent(event, child); done.resolve(event);
          // Dedicated workers also exit successfully when another process owns
          // their advisory lock. That leaves this child inactive; it does not
          // prove an external worker is supervised or require a web restart.
          if (auxiliary && code === 0) onEvent({ event: "auxiliary-inactive", role, pid: child.pid, attempt, reason: "successful-exit" }, child);
          else failed.resolve({ type: "exit", role });
        };
        child.once("error", () => exit(1, null));
        child.once("exit", exit);
        const markReady = () => { onEvent({ event: "ready", role, pid: child.pid, attempt }, child); ready.resolve({ type: "ready" }); };
        if (auxiliary) child.once("spawn", markReady);
        else child.on("message", message => { if (message?.type === "ready" && message.role === role) markReady(); });
        onEvent({ event: "started", role, pid: child.pid, attempt }, child);
        return record;
      };
      const waitReady = async record => {
        let timer;
        const timedOut = new Promise(resolveTimeout => { timer = setTimeout(() => resolveTimeout({ type: "timeout" }), startupMs); });
        try { return await Promise.race([record.ready, failed.promise, stopped.promise, timedOut]); }
        finally { clearTimeout(timer); }
      };
      try {
        let status = await waitReady(start("worker"));
        if (status.type === "ready" && !signal?.aborted) {
          for (const worker of configuration.auxiliaryWorkers ?? []) {
            status = await waitReady(start(worker.role, worker));
            if (status.type !== "ready" || signal?.aborted) break;
          }
        }
        if (status.type === "ready" && !signal?.aborted) status = await waitReady(start("web"));
        if (status.type === "ready" && !signal?.aborted) status = await Promise.race([failed.promise, stopped.promise]);
        if (status.type !== "stop" && !signal?.aborted) onEvent({ event: "generation-failed", reason: status.type, attempt });
      } finally {
        // Do not start a new writer until every process in this generation has
        // exited. Stop the public listener first so no writes reach a draining worker.
        await Promise.all(records.filter(record => record.role === "web").map(record => stopChild(record, shutdownMs)));
        await Promise.all(records.filter(record => record.role !== "web").map(record => stopChild(record, shutdownMs)));
      }
      if (signal?.aborted) return 0;
      if (attempt === maxRestarts) return 1;
      if (!configuration.socketPath) await unlink(socketPath).catch(error => { if (error.code !== "ENOENT") throw error; });
      await Promise.race([delay(restartDelayMs * (attempt + 1)), stopped.promise]);
    }
    return 0;
  } finally {
    signal?.removeEventListener("abort", abort);
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  process.env.NODE_ENV ||= "production";
  // PM2/npm commonly leave the opt-in and SQL settings in .env.local. Load
  // them before making the process topology decision, without logging values.
  require("@next/env").loadEnvConfig(process.cwd(), false, { info() {}, error() {} });
  const configuration = createLaunchConfiguration(process.argv.slice(2), process.env);
  const controller = new AbortController(), stop = () => controller.abort();
  process.on("SIGTERM", stop); process.on("SIGINT", stop);
  try {
    if (configuration.split) process.exitCode = await superviseRuntime(configuration, { signal: controller.signal });
    else {
      const child = spawn(process.execPath, [require.resolve("next/dist/bin/next"), "start", ...configuration.args], {
        env: configuration.env, stdio: "inherit", windowsHide: true,
      });
      const forwardSignal = () => child.kill("SIGTERM");
      controller.signal.addEventListener("abort", forwardSignal);
      process.exitCode = await new Promise(resolveExit => {
        child.once("error", () => resolveExit(1)); child.once("exit", code => resolveExit(code ?? (controller.signal.aborted ? 0 : 1)));
      });
      controller.signal.removeEventListener("abort", forwardSignal);
    }
  } finally { process.off("SIGTERM", stop); process.off("SIGINT", stop); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => {
  console.error(`[runtime] ${error.message}`); process.exitCode = 1;
});
