import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

test('enrichment lets health/import callbacks run during discovery and rescoring without skipping findings',async()=>{
  const source=await readFile('lib/store.ts','utf8');
  const ast=ts.createSourceFile('store.ts',source,ts.ScriptTarget.Latest,true);
  const fn=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='enrichThreatIntel');
  let visited=0,scored=0,discoveryHeartbeat,rescoreHeartbeat,flushed=0;
  const findings=new Map(Array.from({length:1001},(_,i)=>[String(i),{id:String(i),get cves(){visited++;return ['CVE-2026-12345'];},cve:'CVE-2026-12345',cvss:5,epss:0,kev:false,realRisk:1}]));
  const context=vm.createContext({console,Date,setImmediate,store:()=>({findings}),markDirty(){},
    refreshKevFromCisa:async()=>{setImmediate(()=>{discoveryHeartbeat=visited;});return 0;},
    fetchEpss:async()=>new Map([['CVE-2026-12345',.5]]),
    fetchNvd:async()=>{setImmediate(()=>{rescoreHeartbeat=scored;});return new Map();},
    isKev:()=>false,isKevRansomware:()=>false,
    rescoreFinding:(_s,f)=>{scored++;f.realRisk=2;},flushNow:async()=>{flushed++;},
  });
  const code=ts.transpileModule(fn.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const m=new vm.SourceTextModule(code,{context});await m.link(()=>{});await m.evaluate();
  const result=await m.namespace.enrichThreatIntel();
  await new Promise(resolve=>setImmediate(resolve));
  assert.ok(discoveryHeartbeat>0&&discoveryHeartbeat<3003,'discovery must yield before visiting every finding');
  assert.ok(rescoreHeartbeat>0&&rescoreHeartbeat<1001,'rescoring must yield before scoring every finding');
  assert.equal(scored,1001);assert.equal(result.findingsScanned,1001);assert.equal(result.findingsUpdated,1001);
  assert.equal(flushed,1);assert.equal([...findings.values()].every(f=>f.epss===.5&&f.realRisk===2),true);
});
