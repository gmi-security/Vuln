// Standalone operator tool/test loader. Allow only this pure metadata graph;
// importing application stores can start workers or initialize database schema.
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as crypto from 'node:crypto';

export async function loadConnectorPreview() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const allowed = new Set(['customer-connector-preview', 'connectors', 'company-name', 'reporting-direct-sources']
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
      if (spec === 'node:crypto') return new SyntheticModule(Object.keys(crypto), function () {
        for (const key of Object.keys(crypto)) this.setExport(key, crypto[key]);
      });
      if (!spec.startsWith('.')) throw new Error('Unexpected connector preview import.');
      return load(resolve(dirname(file), `${spec}.ts`));
    });
    return mod;
  }
  const mod = await load(resolve(root, 'lib/customer-connector-preview.ts'));
  await mod.evaluate();
  return mod.namespace.buildConnectorPreview;
}
