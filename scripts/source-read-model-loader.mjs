// Restricted standalone parity/test loader: never import application initialization.
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import { createHash } from 'node:crypto';
import ts from 'typescript';

async function loadReader(entry, exportName) {
  const contract = new SourceTextModule(ts.transpileModule(await readFile(new URL('../lib/customer-source-read-model.ts', import.meta.url), 'utf8'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
  await contract.link(() => { throw new Error('Unexpected source contract import.'); });
  const adapter = new SourceTextModule(ts.transpileModule(await readFile(new URL(`../lib/${entry}.ts`, import.meta.url), 'utf8'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
  await adapter.link(name => {
    if (name !== './customer-source-read-model') throw new Error('Unexpected adapter import.');
    return contract;
  });
  await adapter.evaluate();
  return adapter.namespace[exportName];
}
export const loadDefenderSourceReader = () => loadReader('defender-source-read-model', 'createDefenderSourceReader');
export const loadSpotlightSourceReader = () => loadReader('spotlight-source-read-model', 'createSpotlightSourceReader');

export async function loadSpotlightSummaryModules() {
  const allowed = new Set(['customer-source-read-model','spotlight-summary-model','spotlight-summary-store','spotlight-top-fixes','patch-recommendations','crowdstrike-dashboard','elastic-dashboard','remediation-worklist']);
  const cache = new Map();
  function load(name) {
    if (!allowed.has(name)) throw new Error('Unexpected summary dependency.');
    if (cache.has(name)) return cache.get(name);
    const module = new SourceTextModule(ts.transpileModule(readFileSync(new URL(`../lib/${name}.ts`,import.meta.url),'utf8'),
      {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
    cache.set(name,module);
    return module;
  }
  const store = load('spotlight-summary-store');
  await store.link(spec => spec === 'node:crypto'
    ? new SyntheticModule(['createHash'], function(){this.setExport('createHash',createHash);})
    : load(spec.replace(/^\.\//,''))); await store.evaluate();
  return {...store.namespace,...cache.get('spotlight-summary-model').namespace};
}
