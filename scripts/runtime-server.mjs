import http from "node:http";
import { AsyncLocalStorage } from "node:async_hooks";
import { timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { shouldForwardToWorker } from "../lib/runtime-routing.mjs";

const internalHeader = "x-vuln-runtime-token";
const contextKey = Symbol.for("vuln.readContext");
globalThis[contextKey] ??= new AsyncLocalStorage();

function stripInternalCredential(req) {
  delete req.headers[internalHeader];
  req.rawHeaders = req.rawHeaders.filter((_value, index, headers) => headers[index - index % 2].toLowerCase() !== internalHeader);
}

function transportHeaders(headers) {
  const result = { ...headers };
  const connectionHeaders = String(headers.connection ?? "").toLowerCase().split(",").map(value => value.trim());
  for (const name of ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", internalHeader, ...connectionHeaders]) delete result[name];
  return result;
}

function failUnavailable(res) {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify({ error: "The background worker is unavailable. Try again shortly." }));
}

function forward(req, res, socketPath, token) {
  // The destination comes only from the supervisor, never the browser URL or
  // forwarded headers. There is no mutation replay or local fallback.
  const url = new URL(req.url, "http://runtime.local");
  const upstream = http.request({ socketPath, path: `${url.pathname}${url.search}`, method: req.method,
    headers: { ...transportHeaders(req.headers), [internalHeader]: token }, agent: false });
  const cancel = () => upstream.destroy();
  const closed = () => { if (!res.writableEnded) cancel(); };
  req.once("aborted", cancel);
  req.once("error", cancel);
  res.once("close", closed);
  upstream.once("error", () => { req.unpipe(upstream); failUnavailable(res); });
  upstream.once("response", response => {
    if (res.destroyed) { response.destroy(); return; }
    res.writeHead(response.statusCode ?? 502, transportHeaders(response.headers));
    response.once("error", () => failUnavailable(res));
    response.once("aborted", () => { if (!res.destroyed) res.destroy(); });
    response.pipe(res);
  });
  upstream.once("close", () => { req.off("aborted", cancel); req.off("error", cancel); res.off("close", closed); });
  req.pipe(upstream);
}

export function createRuntimeRequestHandler({ role, socketPath, token, handleRequest }) {
  if (!['web', 'worker'].includes(role) || !token || (role === "web" && !socketPath)) throw new Error("Invalid split runtime configuration");
  const expected = Buffer.from(token);
  return (req, res) => {
    const supplied = req.headers[internalHeader];
    stripInternalCredential(req);
    if (role === "worker") {
      const actual = typeof supplied === "string" ? Buffer.from(supplied) : Buffer.alloc(0);
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        res.writeHead(403, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "Forbidden" })); return;
      }
    }
    const run = () => {
      if (role === "web" && shouldForwardToWorker(req.method, req.url)) return forward(req, res, socketPath, token);
      // Next's own proxy and route authorization still run in the selected
      // process. The transport credential never substitutes for application auth.
      Promise.resolve().then(() => handleRequest(req, res)).catch(() => {
        if (res.headersSent) res.destroy();
        else { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "Internal server error" })); }
      });
    };
    if (role === "web") globalThis[contextKey].run({}, run);
    else run();
  };
}

export function startWorkerHealthProbe({ socketPath, token, intervalMs = 10000, timeoutMs = 2000,
  onStatus = status => { globalThis[Symbol.for("vuln.workerHealth")] = status; },
}) {
  let stopped = false, scheduled, deadline, active;
  let status = { available: false, ready: false, blocked: false, checkedAt: new Date().toISOString() };
  onStatus(status);
  const probe = () => {
    if (stopped) return;
    let complete = false;
    const finish = result => {
      if (complete) return;
      complete = true; clearTimeout(deadline); active = undefined;
      if (stopped) return;
      status = { available: result?.available ?? false, ready: result?.ready ?? false,
        blocked: result?.blocked ?? status.blocked, checkedAt: new Date().toISOString() };
      onStatus(status);
      scheduled = setTimeout(probe, intervalMs); scheduled.unref?.();
    };
    const request = http.request({ socketPath, path: "/api/health", method: "GET", agent: false,
      headers: { [internalHeader]: token, accept: "application/json" } }, response => {
      let bytes = 0; const chunks = [];
      response.on("data", chunk => {
        bytes += chunk.length;
        if (bytes > 16384) { request.destroy(); finish(); }
        else chunks.push(chunk);
      });
      response.once("error", () => finish()); response.once("aborted", () => finish());
      response.once("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (![200, 503].includes(response.statusCode) || typeof body.ready !== "boolean" || typeof body.persistence?.blocked !== "boolean") return finish();
          finish({ available: true, ready: response.statusCode === 200 && body.ready && !body.persistence.blocked, blocked: body.persistence.blocked });
        } catch { finish(); }
      });
    });
    active = request;
    request.once("error", () => finish());
    deadline = setTimeout(() => { request.destroy(); finish(); }, timeoutMs); deadline.unref?.();
    request.end();
  };
  probe();
  return () => { stopped = true; clearTimeout(scheduled); clearTimeout(deadline); active?.destroy(); active = undefined; };
}

export async function runRuntimeServer({ env = process.env, createApp } = {}) {
  const role = env.VULN_RUNTIME_ROLE;
  if (!["web", "worker"].includes(role) || !env.VULN_RUNTIME_TOKEN || !env.VULN_RUNTIME_SOCKET) throw new Error("Missing split runtime configuration");
  const hostname = env.VULN_RUNTIME_HOST ?? "0.0.0.0", port = Number(env.VULN_RUNTIME_PORT ?? 3000);
  let stop;
  const stopped = new Promise(resolveStop => { stop = resolveStop; });
  let stopping = false;
  const requestStop = () => { stopping = true; stop(); };
  // Losing the owner is different from its orderly shutdown message: waiting
  // for an in-flight import here could leave an old writer beside a new one.
  const ownerLost = () => process.exit(1);
  const message = value => { if (value?.type === "shutdown") requestStop(); };
  process.on("SIGTERM", requestStop); process.on("SIGINT", requestStop);
  process.on("disconnect", ownerLost); process.on("message", message);
  let app, server, stopHealthProbe;
  try {
    const factory = createApp ?? (await import("next")).default;
    app = await factory({ dev: false, dir: process.cwd(), hostname, port });
    await app.prepare();
    if (stopping) return;
    server = http.createServer(createRuntimeRequestHandler({ role, socketPath: env.VULN_RUNTIME_SOCKET,
      token: env.VULN_RUNTIME_TOKEN, handleRequest: app.getRequestHandler() }));
    if (env.VULN_RUNTIME_KEEP_ALIVE_MS) server.keepAliveTimeout = Number(env.VULN_RUNTIME_KEEP_ALIVE_MS);
    await new Promise((ready, reject) => {
      server.once("error", reject);
      server.listen(role === "worker" ? env.VULN_RUNTIME_SOCKET : { host: hostname, port }, ready);
    });
    server.on("error", requestStop);
    if (role === "web") stopHealthProbe = startWorkerHealthProbe({ socketPath: env.VULN_RUNTIME_SOCKET, token: env.VULN_RUNTIME_TOKEN });
    process.send?.({ type: "ready", role });
    await stopped;
  } finally {
    stopHealthProbe?.();
    if (server?.listening) await new Promise(done => server.close(done));
    await app?.close();
    process.off("SIGTERM", requestStop); process.off("SIGINT", requestStop);
    process.off("disconnect", ownerLost); process.off("message", message);
  }
}

// Existing dedicated workers own their SIGTERM cleanup. The wrapper adds IPC
// ownership so abrupt supervisor loss cannot leave an orphan writer running.
export async function runAuxiliaryWorker(script) {
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    process.emit("SIGTERM");
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on("disconnect", () => process.exit(1));
  process.on("message", message => { if (message?.type === "shutdown") stop(); });
  process.argv = [process.argv[0], script, ...process.argv.slice(3)];
  await import(pathToFileURL(script).href);
  // The underlying worker may naturally finish (disabled, another advisory
  // lock owner, startup failure). IPC must not keep such a process alive.
  process.channel?.unref();
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.VULN_RUNTIME_AUXILIARY === "true") {
    runAuxiliaryWorker(resolve(process.argv[2])).catch(() => process.exit(1));
  } else {
    runRuntimeServer().then(() => process.exit(0), error => {
      console.error(`[runtime] ${error.message}`); process.exit(1);
    });
  }
}
