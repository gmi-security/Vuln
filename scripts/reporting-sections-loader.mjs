// Operator/test loader restricted to pure reporting code; never hydrate a store.
import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {SourceTextModule} from 'node:vm';
import ts from 'typescript';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export async function loadReportingSections(){
 const allowed=new Set(['reporting-sections-accumulator','reporting-metrics','reporting-customer-model','reporting-source-activity']);
 const cache=new Map();
 async function load(name){
  if(!allowed.has(name))throw Error('Unexpected reporting dependency');
  if(cache.has(name))return cache.get(name);
  const code=ts.transpileModule(await readFile(resolve(root,`lib/${name}.ts`),'utf8'),{
   compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code);cache.set(name,mod);
  await mod.link(spec=>load(spec.replace(/^\.\//,'')));return mod;
 }
 const model=await load('reporting-sections-accumulator');await model.evaluate();
 const reference=await load('reporting-customer-model');if(reference.status!=='evaluated')await reference.evaluate();
 return {create:model.namespace.createReportingSectionsAccumulator,reference:reference.namespace.buildCustomerReportingModel};
}
