import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";

async function mount(read, intervalMs) {
  const effects = [];
  const react = new SyntheticModule(["useCallback", "useEffect", "useRef"], function () {
    this.setExport("useCallback", fn => fn);
    this.setExport("useEffect", effect => effects.push(effect));
    this.setExport("useRef", value => ({ current: value }));
  });
  async function load(file) {
    const source = await readFile(new URL(file, import.meta.url), "utf8").catch(error => {
      if (error.code === "ENOENT") return "export {}";
      throw error;
    });
    const module = new SourceTextModule(ts.transpileModule(source, { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
    } }).outputText);
    await module.link(name => {
      if (name === "react") return react;
      if (name === "./browser-polling") return load("../lib/browser-polling.ts");
      throw new Error(`Unexpected dependency ${name}`);
    });
    await module.evaluate(); return module;
  }
  const module = await load("../lib/useBrowserPolling.ts");
  assert.equal(typeof module.namespace.useBrowserPolling, "function");
  const refresh = module.namespace.useBrowserPolling(read, intervalMs);
  const cleanups = effects.map(effect => effect());
  return { refresh, unmount: () => cleanups.forEach(cleanup => cleanup?.()) };
}
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

test("page polling waits for slow reads and manual refresh queues fresh data once", async context => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const requests = [];
  const page = await mount(signal => new Promise(resolve => requests.push({ signal, resolve })), 3000);
  await flush();
  context.mock.timers.tick(9000); await flush(); assert.equal(requests.length, 1);
  const manual = page.refresh();
  requests[0].resolve(); await flush(); assert.equal(requests.length, 2);
  requests[1].resolve(); await manual;
  context.mock.timers.tick(2999); await flush(); assert.equal(requests.length, 2);
  context.mock.timers.tick(1); await flush(); assert.equal(requests.length, 3);
  page.unmount(); requests[2].resolve(); await flush();
});

test("leaving a page aborts its read and prevents a late response or manual refresh from reviving it", async context => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let resolve, signal, published = 0, reads = 0;
  const page = await mount(async current => {
    signal = current; reads++;
    await new Promise(done => { resolve = done; });
    if (!current.aborted) published++;
  }, 4000);
  page.unmount(); assert.equal(signal.aborted, true);
  resolve(); await flush(); await page.refresh(); context.mock.timers.tick(60000); await flush();
  assert.equal(reads, 1); assert.equal(published, 0);
});
