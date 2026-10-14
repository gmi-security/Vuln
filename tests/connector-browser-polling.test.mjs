import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";

const flush = async () => { for (let i = 0; i < 24; i++) await Promise.resolve(); };

async function mount(component, props = {}) {
  const effects = [], updates = [];
  const react = {
    useRef: current => ({ current }),
    useState: initial => [initial, value => updates.push(value)],
    useEffect: effect => effects.push(effect),
  };
  const stub = values => new SyntheticModule(Object.keys(values), function () {
    for (const [key, value] of Object.entries(values)) this.setExport(key, value);
  });
  const iconNames = ["ChevronDown", "ExternalLink", "RefreshCw", "Upload", "IconBug", "IconClipboardCheck", "IconCloudLock", "IconDatabaseCog", "IconDeviceLaptop", "IconPackage", "IconPlugConnected", "IconRadar", "IconShieldSearch", "IconSpider", "IconTopologyStar3"];
  const icons = stub(Object.fromEntries(iconNames.map(name => [name, () => null])));
  const element = (type, props) => ({ type, props });
  const imports = {
    react: stub({ ...react, default: react }),
    "react/jsx-runtime": stub({ jsx: element, jsxs: element, Fragment: "fragment" }),
    "lucide-react": icons,
    "@tabler/icons-react": icons,
    "@/components/VulnShell": stub({ default: "shell" }),
    "@/components/ui": stub({ PanelCard: "panel", Pill: "pill" }),
    "@/lib/connector-import-result": stub({ connectorImportWarnings: () => [] }),
  };
  async function load(path, expose = false) {
    let source = await readFile(new URL(path, import.meta.url), "utf8");
    if (expose) source += "\nexport { SyncAllButton, IntegrationCard };";
    const module = new SourceTextModule(ts.transpileModule(source, { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX,
    } }).outputText);
    await module.link(name => {
      if (name === "@/lib/browser-polling") return load("../lib/browser-polling.ts");
      if (imports[name]) return imports[name];
      throw new Error(`Unexpected dependency ${name}`);
    });
    await module.evaluate(); return module;
  }
  const module = await load("../components/VulnConnectorsPage.tsx", true);
  const tree = module.namespace[component](props);
  const cleanups = effects.map(effect => effect());
  function button(node, label) {
    if (!node || typeof node !== "object") return null;
    if (node.type === "button" && JSON.stringify(node.props.children).includes(label)) return node;
    for (const child of [node.props?.children].flat(Infinity)) {
      const found = button(child, label); if (found) return found;
    }
    return null;
  }
  return { updates, button: label => button(tree, label), unmount: () => cleanups.forEach(cleanup => cleanup?.()) };
}

for (const [component, props, url, label, interval] of [
  ["SyncAllButton", {}, "/api/connectors/sync-all", "Sync all engines", 2000],
  ["IntegrationCard", { card: { id: "tidal", name: "Tidal", configured: true, status: "Connected", capabilities: [], envVars: [] } }, "/api/tidal/import", "Sync now", 1200],
  ["IntegrationCard", { card: { id: "automate", name: "Automate", configured: true, status: "Connected", capabilities: [], envVars: [] } }, "/api/automate/import", "Sync now", 2000],
]) {
  test(`${url}: a manual sync queues behind its mount read and cannot create a second status loop`, async context => {
    context.mock.timers.enable({ apis: ["setTimeout"] });
    const reads = [], mutations = [];
    context.mock.method(globalThis, "fetch", (request, init = {}) => {
      assert.equal(request, url);
      if (init.method === "POST") { mutations.push(request); return Promise.resolve({ ok: true, json: async () => ({}) }); }
      return new Promise(resolve => reads.push({ signal: init.signal, resolve: status => resolve({ ok: true, json: async () => ({ status }) }) }));
    });
    const page = await mount(component, props); await flush();
    assert.equal(reads.length, 1);
    const manual = page.button(label).props.onClick(); await flush();
    context.mock.timers.tick(3 * interval); await flush();
    assert.equal(reads.length, 1, "Manual start cannot overlap the initial read");
    reads[0].resolve({ running: false }); await flush();
    assert.equal(reads.length, 2, "An initial idle response must not discard the manual refresh");
    reads[1].resolve({ running: true }); await manual; await flush();
    context.mock.timers.tick(interval); await flush();
    assert.equal(reads.length, 3);
    context.mock.timers.tick(3 * interval); await flush();
    assert.equal(reads.length, 3, "A slow active status read must not create duplicate polls");
    page.unmount(); assert.equal(reads[2].signal.aborted, true);
    const updates = page.updates.length;
    reads[2].resolve({ running: false }); await flush();
    context.mock.timers.tick(60000); await flush();
    assert.equal(reads.length, 3); assert.equal(page.updates.length, updates);
    assert.equal(mutations.length, 1, "Polling never replays a sync mutation");
  });
}
