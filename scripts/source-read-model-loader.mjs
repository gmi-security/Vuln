// Restricted standalone parity/test loader: never import application initialization.
import { readFile } from 'node:fs/promises';
import { SourceTextModule } from 'node:vm';
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
