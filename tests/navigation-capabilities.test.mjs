import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";

async function load(path) {
  const source = await readFile(new URL(path, import.meta.url), "utf8").catch(error => {
    if (error.code === "ENOENT") return "export {}";
    throw error;
  });
  const module = new SourceTextModule(ts.transpileModule(source, { compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
  } }).outputText);
  await module.link(name => {
    assert.equal(name, "lucide-react");
    const names = ["Bug", "Building2", "CalendarClock", "ClipboardCheck", "Database", "Flame", "GitBranch", "LayoutDashboard", "PlugZap", "Radar", "ScanSearch", "Share2", "ShieldCheck", "SlidersHorizontal", "Timer"];
    return new SyntheticModule(names, function () { for (const key of names) this.setExport(key, key); });
  });
  await module.evaluate(); return module.namespace;
}
const { siteNavigation } = await load("../lib/navigation.ts");
const capabilities = await load("../lib/navigation-capabilities.ts");

test("unknown capability state keeps the Remediation destination visible while an explicit disabled response removes it", () => {
  assert.equal(siteNavigation(null).primary.some(item => item.href === "/remediation"), true);
  assert.equal(siteNavigation({ enabled: true, remediationEnabled: false }).primary.some(item => item.href === "/remediation"), false);
  assert.equal(siteNavigation({ enabled: false, remediationEnabled: false }).primary.some(item => item.href === "/remediation"), false);
});

test("malformed or failed capability reads cannot silently become a disabled feature response", async () => {
  assert.equal(typeof capabilities.readNavigationCapabilities, "function");
  for (const response of [new Response("{}"), new Response("[]"), new Response("{\"enabled\":\"true\"}"), new Response("bad gateway", {status:502})]) {
    await assert.rejects(capabilities.readNavigationCapabilities(response));
  }
  assert.deepEqual(await capabilities.readNavigationCapabilities(new Response('{"enabled":true,"remediationEnabled":true}')), { enabled:true, remediationEnabled:true });
  assert.deepEqual(await capabilities.readNavigationCapabilities(new Response('{"enabled":true}')), { enabled:true, remediationEnabled:false });
  assert.deepEqual(await capabilities.readNavigationCapabilities(new Response('{"enabled":false,"remediationEnabled":true}')), { enabled:false, remediationEnabled:false });
});
