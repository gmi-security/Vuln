import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const path = resolve('lib/reporting-tenant-scope.ts');
const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const module = new SourceTextModule(code, { identifier: path });
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { customerFalconTenantIds } = module.namespace;
const cid = 'a'.repeat(32);

test('only Atlas receives verified configured Falcon tenant IDs', () => {
  assert.deepEqual(customerFalconTenantIds('CO-147284', `${cid}, ${cid}, ${'b'.repeat(32)}`), [cid, 'b'.repeat(32)]);
  assert.deepEqual(customerFalconTenantIds('CO-2', cid), []);
  assert.deepEqual(customerFalconTenantIds('', cid), []);
});

test('invalid or absent tenant mappings cannot assign historical drafts', () => {
  assert.deepEqual(customerFalconTenantIds('CO-147284', 'Atlas Healthcare,not-a-cid'), []);
  assert.deepEqual(customerFalconTenantIds('CO-147284', undefined), []);
});
