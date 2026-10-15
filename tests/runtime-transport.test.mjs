import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";

const runtime = await import("../scripts/runtime-server.mjs").catch(error => {
  if (error.code === "ERR_MODULE_NOT_FOUND") return {};
  throw error;
});
const token = "test-runtime-token-that-is-never-a-browser-credential";
const internalHeader = "x-vuln-runtime-token";
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

async function listen(context, handler, address = { host: "127.0.0.1", port: 0 }) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(address, resolve); });
  context.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return typeof address === "string" ? { socketPath: address } : { host: "127.0.0.1", port: server.address().port };
}

async function socket(context) {
  if (process.platform === "win32") return `\\\\.\\pipe\\vuln-test-${randomUUID()}`;
  const dir = await mkdtemp(join(tmpdir(), "vuln-test-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  return join(dir, "worker.sock");
}

function request(address, options = {}, body = "") {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...address, path: "/api/companies", ...options }, res => {
      const chunks = [];
      res.on("data", chunk => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject); req.end(body);
  });
}

test("worker rejects untrusted direct requests before application auth and strips its transport credential", async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  let handled = 0;
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "worker", token, handleRequest(req, res) {
    handled++;
    assert.equal(req.headers[internalHeader], undefined);
    assert.equal(req.rawHeaders.some(value => value === token), false);
    res.statusCode = req.headers.cookie === "session=valid" ? 200 : 401; res.end("application auth");
  } }), await socket(context));
  for (const headers of [{}, { [internalHeader]: "wrong" }, { [internalHeader]: [token, token] }]) {
    assert.equal((await request(address, { headers })).status, 403);
  }
  assert.equal(handled, 0);
  assert.equal((await request(address, { headers: { [internalHeader]: token } })).status, 401);
  assert.equal((await request(address, { headers: { [internalHeader]: token, cookie: "session=valid" } })).status, 200);
});

test("proxy streams a mutation to the fixed private socket preserving application auth and response headers", async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  const socketPath = await socket(context), receivedFirst = deferred();
  await listen(context, runtime.createRuntimeRequestHandler({ role: "worker", token, handleRequest(req, res) {
    assert.equal(req.url, "/api/companies?customer=one");
    assert.equal(req.headers.host, "vuln.example.test");
    assert.equal(req.headers.origin, "https://vuln.example.test");
    assert.equal(req.headers.cookie, "session=valid");
    let body = "";
    req.on("data", chunk => { body += chunk; receivedFirst.resolve(); });
    req.on("end", () => { res.writeHead(202, { "content-type": "text/plain", "set-cookie": ["a=1", "b=2"] }); res.end(body); });
  } }), socketPath);
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "web", socketPath, token,
    handleRequest(_req, res) { res.statusCode = 500; res.end("wrong process"); } }));
  const result = new Promise((resolve, reject) => {
    const req = http.request({ ...address, path: "http://attacker.invalid/api/companies?customer=one", method: "POST", headers: {
      host: "vuln.example.test", origin: "https://vuln.example.test", cookie: "session=valid", [internalHeader]: "attacker",
    } }, res => { let body = ""; res.on("data", chunk => { body += chunk; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body })); });
    req.on("error", reject); req.write("first-");
    receivedFirst.promise.then(() => req.end("last"));
  });
  const response = await result;
  assert.equal(response.status, 202);
  assert.equal(response.body, "first-last");
  assert.deepEqual(response.headers["set-cookie"], ["a=1", "b=2"]);
});

test("missing worker fails closed without executing or retrying a mutation on web", async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  let localCalls = 0;
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "web", socketPath: await socket(context), token,
    handleRequest(_req, res) { localCalls++; res.end("local"); } }));
  const response = await request(address, { method: "POST" }, "body");
  assert.equal(response.status, 503);
  assert.equal(localCalls, 0);
  assert.equal((await request(address)).body, "local");
  assert.equal(localCalls, 1);
});

test("browser upload abort closes the private request", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  const socketPath = await socket(context), started = deferred(), aborted = deferred();
  await listen(context, (req, res) => {
    req.on("data", () => started.resolve());
    req.on("aborted", () => aborted.resolve());
    req.on("error", () => {});
  }, socketPath);
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "web", socketPath, token, handleRequest() {} }));
  const req = http.request({ ...address, path: "/api/companies", method: "POST" });
  req.on("error", () => {}); req.write("partial upload");
  await started.promise; req.destroy(); await aborted.promise;
});

test("browser response abort closes the private response stream", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  const socketPath = await socket(context), closed = deferred();
  await listen(context, (_req, res) => { res.on("close", () => closed.resolve()); res.writeHead(200); res.write("partial response"); }, socketPath);
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "web", socketPath, token, handleRequest() {} }));
  const req = http.request({ ...address, path: "/api/crowdstrike/import" });
  req.on("error", () => {}); req.end();
  const [res] = await once(req, "response"); res.destroy(); await closed.promise;
});

test("parallel web requests get independent committed-read contexts and cannot inject the internal token", async context => {
  assert.equal(typeof runtime.createRuntimeRequestHandler, "function");
  const contexts = new Set(), firstStarted = deferred(), release = deferred();
  const address = await listen(context, runtime.createRuntimeRequestHandler({ role: "web", socketPath: await socket(context), token,
    async handleRequest(req, res) {
      const local = globalThis[Symbol.for("vuln.readContext")].getStore();
      assert.ok(local); contexts.add(local);
      assert.equal(req.headers[internalHeader], undefined);
      assert.equal(req.rawHeaders.includes("browser-secret"), false);
      if (req.url.endsWith("one")) { local.snapshot = "first"; firstStarted.resolve(); await release.promise; assert.equal(local.snapshot, "first"); }
      else { assert.equal(local.snapshot, undefined); local.snapshot = "second"; release.resolve(); }
      res.end(local.snapshot);
    } }));
  const one = request(address, { path: "/api/companies?one", headers: { [internalHeader]: "browser-secret" } });
  await firstStarted.promise;
  const two = request(address, { path: "/api/companies?two" });
  assert.deepEqual((await Promise.all([one, two])).map(response => response.body), ["first", "second"]);
  assert.equal(contexts.size, 2);
});

for (const ending of ['finish', 'abort', 'throw']) test(`web ${ending} releases the pinned view retained by background async resources`, {timeout:5000}, async context => {
  const started=deferred(), release=deferred(), ended=deferred(); let local;
  const view={findings:new Map([['f',{id:'f'}]])};
  const address=await listen(context,runtime.createRuntimeRequestHandler({role:'web',socketPath:await socket(context),token,
    async handleRequest(_req,res){
      local=globalThis[Symbol.for('vuln.readContext')].getStore(); local.platform=view;
      res.once('close',()=>ended.resolve()); started.resolve();
      if(ending==='throw')throw Error('test handler failure');
      res.write('stream'); await release.promise;
      if(ending==='finish'){assert.equal(local.platform,view,'active streaming request keeps its pinned generation');res.end('end');}
    }}));
  const req=http.request({...address,path:'/api/companies'});req.on('error',()=>{});req.end();
  const [res]=await once(req,'response'); res.resume(); await started.promise;
  if(ending==='abort')res.destroy(); else release.resolve();
  await ended.promise;
  assert.equal(local.platform,undefined,'completed requests must not retain the full platform dataset');
  local.platform=view;
  assert.equal(local.platform,undefined,'late async work must not repin a completed request');
  release.resolve();
});
