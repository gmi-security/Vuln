import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
const m=new SourceTextModule(ts.transpileModule(await readFile('lib/connector-import-result.ts','utf8'),
  {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
await m.link(()=>{throw new Error('No dependencies expected');});await m.evaluate();const {connectorImportWarnings:warnings}=m.namespace;
test('successful, empty and already-imported results are not reported as failures',()=>{
 for(const value of [null,undefined,[],{}, {assetsUpserted:0}, {errors:[],tenants:[{assetsUpserted:1}]},
   {skipped:[{reason:'already imported'},{reason:'status running'}]}])assert.deepEqual(warnings(value),[]);
});
test('partial import errors, failed tenants and truncated results remain visible without raw details',()=>{
 const messages=warnings({assetsUpserted:50,errors:['secret response'],tenants:[{error:'private details'},{assetsUpserted:50}],truncatedTenants:['private tenant']});
 assert.equal(messages.length,3);assert.match(messages.join(' '),/1 import error/);assert.match(messages.join(' '),/1 tenant import failed/);
 assert.match(messages.join(' '),/incomplete/);assert.doesNotMatch(messages.join(' '),/secret|private/);
});
test('mapping conflicts are visible while ordinary skipped records remain distinct',()=>{
 const messages=warnings({skipped:[{reason:'no unambiguous matching company'},
   {reason:'existing scan belongs to a different company; review its mapping'},{reason:'already imported'}]});
 assert.deepEqual(messages,['2 customer mappings need review']);
});
