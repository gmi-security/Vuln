// Standalone operator tool/test loader. Allow only this pure metadata graph;
// importing application stores can start workers or initialize database schema.
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import * as metadata from '../lib/db/connector-metadata.mjs';

async function loadConnectorModule(entry) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const allowed = new Set(['customer-elastic-scope', 'customer-query-routing', 'customer-scanner-routing', 'scanner-target-scope', 'customer-operational-routing', 'customer-spotlight-routing', 'customer-inventory-routing', 'customer-connector-routing', 'connector-data-contracts', 'customer-connector-preview', 'customer-connector-drafts', 'customer-connector-bindings', 'customer-connector-status', 'customer-saved-source-bindings', 'customer-saved-sources', 'connectors', 'company-name', 'reporting-direct-sources']
    .map(name => resolve(root, `lib/${name}.ts`)));
  const cache = new Map();
  async function load(file) {
    if (!allowed.has(file)) throw new Error('Unexpected connector preview dependency.');
    if (cache.has(file)) return cache.get(file);
    const code = ts.transpileModule(await readFile(file, 'utf8'), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    }).outputText;
    const mod = new SourceTextModule(code, { identifier: file });
    cache.set(file, mod);
    await mod.link(spec => {
      if (spec === './db/connector-metadata.mjs') return new SyntheticModule(Object.keys(metadata), function () {
        for (const key of Object.keys(metadata)) this.setExport(key, metadata[key]);
      });
      if (spec === 'node:net') return new SyntheticModule(Object.keys(net), function () { for (const key of Object.keys(net)) this.setExport(key,net[key]); });
      if (spec === 'node:crypto') return new SyntheticModule(Object.keys(crypto), function () {
        for (const key of Object.keys(crypto)) this.setExport(key, crypto[key]);
      });
      if (!spec.startsWith('.')) throw new Error('Unexpected connector preview import.');
      return load(resolve(dirname(file), `${spec}.ts`));
    });
    return mod;
  }
  const mod = await load(resolve(root, `lib/${entry}.ts`));
  await mod.evaluate();
  return mod.namespace;
}

export async function loadConnectorPreview() {
  return (await loadConnectorModule('customer-connector-preview')).buildConnectorPreview;
}
export async function loadConnectorDraftStore() {
  return (await loadConnectorModule('customer-connector-drafts')).createConnectorDraftStore;
}
export async function loadConnectorStatus() {
  return (await loadConnectorModule('customer-connector-status')).customerConnectorStatus;
}
export async function loadConnectorBindingStore() {
  return (await loadConnectorModule('customer-connector-bindings')).createConnectorBindingStore;
}
export const loadSavedSourceBindings = () => loadConnectorModule('customer-saved-source-bindings');
export const loadConnectorContracts = () => loadConnectorModule('connector-data-contracts');
export const loadConnectorReview = () => loadConnectorModule('customer-connector-drafts');
export const loadConnectorRouting = () => loadConnectorModule('customer-connector-routing');
export const loadInventoryRouting = () => loadConnectorModule('customer-inventory-routing');

export const loadSpotlightRouting = () => loadConnectorModule('customer-spotlight-routing');

export const loadScannerRouting = () => loadConnectorModule('customer-scanner-routing');
export const loadScannerTargets = () => loadConnectorModule('scanner-target-scope');

export const loadQueryRouting = () => loadConnectorModule("customer-query-routing");

export const loadElasticScope = () => loadConnectorModule("customer-elastic-scope");
